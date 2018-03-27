#-*- coding:utf-8 -*-
import socket
from random import randint
import _thread
from struct import unpack, pack
from socket import inet_aton, inet_ntoa
from time import sleep, time
import os
import binascii
import math
import logging
from hashlib import sha1
from bcoding import bencode, bdecode
from bisect import bisect_left
from bisect import bisect_right
from threading import Thread
import queue
BT_PROTOCOL = "BitTorrent protocol"
BT_MSG_ID = 20
EXT_HANDSHAKE_ID = 0
def entropy(bytes):
    s = ""
    for i in range(bytes):
        s += chr(randint(0, 255))
    return s   
def random_id(size=20):
    hash = sha1()
    hash.update( entropy(20).encode("utf8") )
    return hash.digest()
def send_handshake(the_socket, infohash):
    bt_header = chr(len(BT_PROTOCOL)) + BT_PROTOCOL
    ext_bytes = "\x00\x00\x00\x00\x00\x10\x00\x00"
    peer_id = random_id()
    packet = bt_header.encode() + ext_bytes.encode() + infohash + peer_id
    send_packet(the_socket, packet)

def send_packet(the_socket, msg):
    the_socket.send(msg)
    
def send_ext_handshake(the_socket):
    msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE_ID).encode() + bencode({"m":{"ut_metadata": 2}})
    send_message(the_socket, msg)
def send_message(the_socket, msg):
    msg_len = pack(">I", len(msg))
    send_packet(the_socket, msg_len + msg)
def get_ut_metadata(data):
    try:
        ut_metadata = "ut_metadata"
        index = data.index(ut_metadata.encode())+len(ut_metadata) + 1
        data = data[index:]
        return int(data[:data.index("e".encode())])
    except Exception:
        return -1
    
def request_metadata(the_socket, ut_metadata, piece):
    """bep_0009"""
    msg = chr(BT_MSG_ID).encode() + chr(ut_metadata).encode() + bencode({"msg_type": 0, "piece": piece})
    send_message(the_socket, msg)
def get_metadata_size(data):
    metadata_size = "metadata_size"
    start = data.index(metadata_size.encode()) + len(metadata_size) + 1
    data = data[start:]
    return int(data[:data.index("e".encode())])
def recvall(the_socket, data):
    begin = time()
    data=data+ the_socket.recv(1024*3)
    try:
        a=data.index("ee".encode())
        b=data.index("pieces".encode())
    except:
        return recvall(the_socket,data)
    #print(data[a+2:b-2])
    return data[a+2:b-2]
def dealMsg(data):
    pass
    
adrr=('94.158.68.67', 30670)
infohash=b'\xc3\x9d\x89\xdaR0\xbd\xbd\x1a\x00\xf8n\x04\xa3Y\x1f\x96\xfe\xc6\xbc'
#adrr=('125.77.58.208', 9639)
#infohash=b'Q\x1b\xb4B\x04\xe5\x92\x8c\xcd\x1d\xebp\x13\x94\x03\x82|\n\x83v'
def getInfoMessage(adrr,infohash,infohash2,mu):
    try:
        begin = time()
        the_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        the_socket.connect(adrr)
        
        #print(type(infohash))
        send_handshake(the_socket, infohash)
        packet = the_socket.recv(4096)
        #print(packet)
        if(packet=="".encode()):
            the_socket.close()
            return
        ut_metadata=get_ut_metadata(packet)
        send_ext_handshake(the_socket)
        if(ut_metadata==-1): 
            packet=the_socket.recv(4096)
        ut_metadata, metadata_size = get_ut_metadata(packet), get_metadata_size(packet)
        #print("ut_metadata,and metadata_size")
        #print(ut_metadata,metadata_size)
        request_metadata(the_socket, ut_metadata, 0)
        packet = recvall(the_socket, "".encode()) #the_socket.recv(1024*17)
        metadata=packet    
        #print(metadata)        
        result=bdecode(metadata)
        
        #if mu.acquire(True):
            #print("ddddddddddddddddddddddd")
        f = open('cili5.txt','a',encoding='utf-8')
        print(result["name"])
        f.write(infohash2+" "+result["name"]+"\n")
        f.close()
            #mu.release()
        print(time()-begin)
        the_socket.close()
        #raise RuntimeError('testError')
    except :
        #raise
        return 


