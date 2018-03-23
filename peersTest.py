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
    print(type(bt_header))
    print(type(ext_bytes))
    print(type(peer_id))
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
    ut_metadata = "ut_metadata"
    index = data.index(ut_metadata.encode())+len(ut_metadata) + 1
    data = data[index:]
    return int(data[:data.index("e".encode())])
def request_metadata(the_socket, ut_metadata, piece):
    """bep_0009"""
    msg = chr(BT_MSG_ID).encode() + chr(ut_metadata).encode() + bencode({"msg_type": 0, "piece": piece})
    send_message(the_socket, msg)
def get_metadata_size(data):
    metadata_size = "metadata_size"
    start = data.index(metadata_size.encode()) + len(metadata_size) + 1
    data = data[start:]
    return int(data[:data.index("e".encode())])
def get_peer(the_socket,info):
    msg={"t":"jdj", "y":"q","q":"get_peers", "a":{"id":random_id(),"info_hash":info}}
    the_socket.send(bencode(msg))
def recvall(the_socket, timeout=5):
    total_data ="".encode()
    the_socket.setblocking(0)
    data = ""
    begin = time()
    i=1
    while True:
        sleep(0.05)
        if total_data and time()-begin > timeout:
            break
        elif time()-begin > timeout*2:
            break
        try:
            data = the_socket.recv(1024*17)
            i=i+1
            if data:
                total_data=total_data+data
                #print(total_data)
                begin = time()
                print(i)
        except Exception:
            pass
            #raise
    #print((total_data))
    return total_data
adrr=('112.101.13.211', 26165)
the_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
the_socket.connect(adrr)
        # handshake
infohash=b'\x14)B\xffU>\xc6\x13\xbb\xa0`t_v\xd9o4\xc5\x91;'
print(type(infohash))
#send_handshake(the_socket, infohash)
get_peer(the_socket,infohash)
packet,address = the_socket.recvfrom(65536)
print(packet)
print(bdecode(packet))
print("1111")
send_ext_handshake(the_socket)
packet = the_socket.recv(4096)
print(packet)

print("333")
ut_metadata, metadata_size = get_ut_metadata(packet), get_metadata_size(packet)
print(ut_metadata)
print(metadata_size)
