#-*- coding:utf-8 -*-
import socket
from random import randint
import _thread
from struct import unpack, pack
from socket import inet_aton, inet_ntoa
import time
import os
import binascii
import logging
from hashlib import sha1
from bcoding import bencode, bdecode
K = 8
HOST = '0.0.0.0'  
PORT = 6881  
class KNode(object):
     # """
     #节点信息包括nodeId ip 与port端口
     # """ 
    __slots__ = ("nid", "ip", "port")
    
    def __init__(self, nid, ip, port):
        self.nid = nid
        self.ip = ip
        self.port = port
    def __eq__(self, other):
        return self.nid == other.nid
class KBucket(object):
    __slots__ = ("min", "max", "nodes")  
    def __init__(self, min, max):
        self.min = min
        self.max = max
        self.nodes = []
    def in_range(self, target):
        return self.min <= intify(target) < self.max
#解析收到的nodes
def decode_nodes(nodes):
    n = []
    length = len(nodes)
    if (length % 26) != 0: 
        return n
    for i in range(0, length, 26):
        nid = nodes[i:i+20]
        ip = inet_ntoa(nodes[i+20:i+24])
        port = unpack("!H", nodes[i+24:i+26])[0]
        n.append( (nid, ip, port) )
    return n
#组装nodes
def encode_nodes(nodes):
    strings = []
    for node in nodes:
        s = "%s%s%s" % (node.nid, inet_aton(node.ip), pack("!H", node.port))
        strings.append(s)

    return "".join(strings)

def intify(hstr):
    #"""这是一个小工具, 把一个node ID转换为数字. 后面会频繁用到.""" 
    return  str(int(binascii.hexlify(hstr), 16)) #先转换成16进制, 再变成数字

def entropy(bytes):
    s = ""
    for i in range(bytes):
        s += chr(randint(0, 255))
    return s   
def random_id(size=20):
    
    hash = sha1()
    hash.update( entropy(20).encode("utf8") )
    return hash.digest()
def getMessage(s):
    while True:  
        data,address = s.recvfrom(1024)
        a=bdecode(data)
        try: 
            if(a["y"]=="r"):
                if(a["t"]=="mycode"):
                    continue
                nodes=decode_nodes(a["r"]["nodes"])
                #print (address)
                dealNodes(nodes,s)
            else:
                print (a)
                continue
        except KeyError:
                print(a)
                continue
def dealNodes(nodes,s):
    d=2
    for node in nodes:
        if(intify(NodeId)==intify(node[0])):
            d=4
            break
        msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":NodeId,"target":NodeId}}
        if(d==4):
            print(d)
        s.sendto(bencode(msg),(node[1],node[2]))
print("start")
NodeId=random_id()

print(NodeId)
print(str(int(binascii.hexlify(NodeId), 16)))
ServerName = 'router.utorrent.com'
ServerPort = 6881
clientSocket =socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
clientSocket.bind((HOST,PORT))
msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":NodeId,"target":NodeId}}
clientSocket.sendto(bencode(msg),(ServerName,ServerPort))
_thread.start_new_thread( getMessage, (clientSocket, ) )


