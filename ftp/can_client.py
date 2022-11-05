from socket import *
import json
import os
from os.path import join, getsize

import argparse
from threading import Thread
import struct
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil
import hashlib
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("-server_ip", "--server_ip",required=True, dest="ip",
                       help="server ip")
    parse.add_argument("-id", "--port",default='1379', required=True, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("-f", "--path", required=True, dest="path",
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
    j = json.dumps(dict(json_data), ensure_ascii=False)#json.dumps() 是把python对象转换成json对象的一个过程，生成的是字符串。
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()#struct.pack用于将Python的值根据格式符，转换为字节数组。
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data





def make_request_packet(operation, data_type, json_data, bin_data=None):
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    # json_data[FIELD_STATUS] = status_code
    # json_data[FIELD_STATUS_MSG] = status_msg
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

def tcp_connection(ip,port,filepath):
    client = socket()
    client.connect(ip, port)
    login_data = {
        {
            FIELD_USERNAME: "first",
            FIELD_PASSWORD: hashlib.md5(FIELD_USERNAME.encode()).digest(),  # md5写死
        }
    }
    client.send(make_request_packet(OP_LOGIN, TYPE_AUTH, login_data))
    json_data, bin_data = get_tcp_packet(client)
    if json_data[FIELD_STATUS] == 200:
        print("Token is %s" % json_data[FIELD_TOKEN])

    # op_save
    file = open(filepath, 'rb')
    filename=filepath.split('/')[-1]
    a = hashlib.md5(file)
    file_md5 = a.digest()
    file_size = os.path.getsize(filepath)
    file_header = {
        {
            FIELD_KEY: filename,
            FIELD_SIZE: file_size,
            FIELD_TOKEN: json_data[FIELD_TOKEN],
        }
    }
    # 把filename 当作 key
    file = open(filepath, 'rb').read()
    client.send(make_request_packet(OP_SAVE, TYPE_DATA, file_header))
    json_data, bin_data = get_tcp_packet(client)
    block_size=json_data[FIELD_BLOCK_SIZE]
    total_block = json_data[FIELD_TOTAL_BLOCK]
    block_index=0


    #op_upload
    while True:
        data={
            FIELD_BLOCK_INDEX:block_index
        }
        content=file[block_size*block_index: block_size*(block_index+1)]
        client.send(make_request_packet(OP_UPLOAD,TYPE_FILE,data,content))
        block_index=block_index+1
        if block_index == total_block:
            break;
    json_data, bin_data = get_tcp_packet(client)
    if file_md5 == json_data[FIELD_MD5]:
        print("successful transfer")



# block_index=0


def main():
    client = socket()
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    filepath=parser.path
    while True:
        th = Thread(target=tcp_connection,args=(server_ip,server_port,filepath))





if __name__ == '__main__':
    main()