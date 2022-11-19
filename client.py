import logging
from socket import *
import json
import os
import argparse
import struct
import time
import hashlib
import time
from tqdm import tqdm

OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("-server_ip", default='', action='store', required=False, dest="ip",
                       help="server ip")
    parse.add_argument("-port", default=1379, action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("-id", default=2035965, action='store', required=False, dest="id",
                       help="id is the student ID number")
    parse.add_argument("-f", action='store', required=False, dest="path",
                       help="input the path of file")
    return parse.parse_args()


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    # transform json into str
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    # pack binary data
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def make_request_packet(operation, data_type, json_data, bin_data=None):
    """
    a shortcut to make packer from fields
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)


def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


class Client():
    """
    Upload file Client.
    """

    def __init__(self, ip, port) -> None:
        self.connection = socket(AF_INET, SOCK_STREAM)
        self.ip = ip
        self.port = int(port)
        self.connection.connect((self.ip, self.port))

    def authorization(self):
        """
        perform operation login (OP_LOGIN)
        """
        login_data = {
            FIELD_USERNAME: "2035965"
        }
        # generate password
        login_data[FIELD_PASSWORD] = str(hashlib.md5(
            login_data[FIELD_USERNAME].encode()).hexdigest())
        # send login packet
        self.connection.send(make_request_packet(
            OP_LOGIN, TYPE_AUTH, login_data))
        # get login response
        json_data, bin_data = get_tcp_packet(self.connection)
        if json_data[FIELD_STATUS] == 200:
            logging.info(
                "Login successfully. Token : {%s}" % json_data[FIELD_TOKEN])
        self.session_token = json_data[FIELD_TOKEN]

    def save(self, filepath):
        """
        perform operation save (OP_SAVE)
        """
        filename = filepath.split('/')[-1]
        file_size = os.path.getsize(filepath)
        file_header = {
            # set key as filename
            FIELD_KEY: filename,
            FIELD_SIZE: file_size,
            FIELD_TOKEN: self.session_token,
        }
        self.connection.send(make_request_packet(
            OP_SAVE, TYPE_FILE, file_header))
        json_data, _ = get_tcp_packet(self.connection)
        block_size = json_data[FIELD_BLOCK_SIZE]
        total_block = json_data[FIELD_TOTAL_BLOCK]
        return block_size, total_block

    def delete(self, key):
        self.connection.send(make_request_packet(
            OP_DELETE, TYPE_DATA, {FIELD_KEY: key}))
        json_data, _ = get_tcp_packet(self.connection)
        logging.info(json_data[FIELD_STATUS_MSG])

    def upload(self, filepath):
        """
        perform operation upload (OP_UPLOAD)
        """
        filename = filepath.split('/')[-1]
        block_size, total_block = self.save(filepath)
        file = open(filepath, 'rb').read()
        file_md5 = hashlib.md5(file).hexdigest()

        block_index = 0
        start_time = time.time()

        # upload block by block
        for i in tqdm(range(total_block)):
            data = {
                FIELD_BLOCK_INDEX: block_index,
                FIELD_TOKEN: self.session_token,
                FIELD_KEY: filename
            }
            content = file[block_size*block_index: block_size*(block_index+1)]
            self.connection.send(make_request_packet(
                OP_UPLOAD, TYPE_FILE, data, content))
            block_index = block_index+1
            json_data, bin_data = get_tcp_packet(self.connection)
        
        total_time = time.time() - start_time
        logging.info(f"Send completely. Cost {total_time:.2f}s, {total_time/total_block:.2f}s per block.")
        
        if file_md5 == str(json_data[FIELD_MD5]):
            logging.info("successful transfer.")
        else:
            if not hasattr(self, "retry"):
                self.retry = 0
            else:
                self.retry += 1

            if self.retry < 3:
                logging.error(
                    f"md5 is different. Delete the wrong file. KEY: {filename}. Retry {3 - self.retry}")
                self.delete(filename)
                self.upload(filepath)
            else:
                logging.critical(
                    f"KEY: {filename} has been send for 3 times. There still something wrong. Client give up.")


logging.basicConfig(
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler()
    ]
)


def main():
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    filepath = parser.path
    logging.info("begin to transfer")
    client = Client(server_ip, server_port)
    client.authorization()
    client.upload(filepath)


if __name__ == '__main__':
    main()
