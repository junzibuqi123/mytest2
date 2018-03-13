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
from bisect import bisect_left
from bisect import bisect_right
K = 8
HOST = '0.0.0.0'  
PORT = 6884  
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
        return self.min <= int(intify(target)) < self.max
    def append(self, node):
                self.nodes.append(node)
    def remove(self, node):
        self.nodes.remove(node)
class Ktable(object):        
        def __init__(self, nid):       
                self.nid = nid
                self.kbs = []
        def append(self, KBucket):
                self.kbs.append(KBucket)
        def minlist(self):
                return list(map(lambda k:k.min,self.kbs))
        def copyTwo(self,index):
                kb=self.kbs[index]
                point = kb.max - (kb.max - kb.min)/2
                new = KBucket(point, kb.max)
                kb.max = point
                self.kbs.insert(index + 1, new)
                for node in kb.nodes[:]:
                    if new.in_range(node.nid):
                        new.append(node)
                        kb.remove(node)


                
        def dealNode(self,node):
            flag=True
            br=bisect_right(self.minlist(), int(intify(node.nid)))
            index = br-1
            kb=self.kbs[index]
            #print(len(self.kbs))
            for n in kb.nodes:
                if int(intify(n.nid))==int(intify(node.nid)):
                    #print("dddd1")
                    flag=False
            if flag:
                if len(kb.nodes)==8:
                    #print("dddd2")
                    self.copyTwo(index)
                    return True
                else:
                    kb.nodes.append(node)
                    return True
            return False
            
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
def proper_infohash(infohash):
    if isinstance(infohash, bytes):
        # Convert bytes to hex
        infohash = binascii.hexlify(infohash).decode('utf-8')
    return infohash.upper()

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
        msg=bdecode(data)
        msg_type = msg.get("y", "e")
        #print(msg_type)
        #print(msg)
        try:
            if msg_type == "e":
                return

            if(msg_type == "r"):
                nodes=decode_nodes(msg["r"]["nodes"])
                #print (address)
                dealFindNodesBack(nodes,s)
            if(msg_type=="q"):
                if msg["q"]=="ping":
                    dealPing(msg,s,address)
                if msg["q"]=="find_node":
                    dealFideNodes(msg,s,address)
                if msg["q"]=="get_peers":
                    dealGetPeer(msg,s,address)
                if msg["q"]=="announce_peer":
                    dealAnnouncePeer(msg,s,address)
        except KeyError:
                print(msg)
                continue
def dealFindNodesBack(nodes,s):
    for node in nodes:
        if kt.dealNode(KNode(node[0],node[1],node[2])):
            msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":NodeId,"target":NodeId}}
            s.sendto(bencode(msg),(node[1],node[2]))
def dealPing(msg,s,adress):
    print("p")
    tid=msg['t']
    msg={"t":tid, "y":"r", "r":{"id":NodeId}}
    s.sendto(bencode(msg),(adress))
    return
def dealFideNodes(msg,s,adress):
    print("fn")
    tid=msg['t']
    msg={"t":tid, "y":"r", "r":{"id":NodeId,"nodes":""}}
    s.sendto(bencode(msg),(adress))
    return
def dealGetPeer(msg,s,adress):
    tid=msg['t']
    infohash = msg["a"]["info_hash"]
    infohash = proper_infohash(infohash)
    print("getPeer: "+infohash)    
    token = infohash[:2]
    msg={"t":tid, "y":"r", "r":{"id":NodeId,"nodes":"", "token":token}}
    s.sendto(bencode(msg),(adress))     
    return
def dealAnnouncePeer(msg,s,adress):
    infohash = msg["a"]["info_hash"]
    infohash = proper_infohash(infohash)
    print("AnnouncePeer: "+infohash)    
    return
print("start")
NodeId=random_id()
kt=Ktable(NodeId)
kb=KBucket(0,2**160)
kt.append(kb)
print(NodeId)
print(str(int(binascii.hexlify(NodeId), 16)))
ServerName = 'router.utorrent.com'
ServerPort = 6881
clientSocket =socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
clientSocket.bind((HOST,PORT))
msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":NodeId,"target":NodeId}}
clientSocket.sendto(bencode(msg),(ServerName,ServerPort))
_thread.start_new_thread( getMessage, (clientSocket, ) )


