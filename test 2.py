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
import queue
K = 8

LOCAL_ADDR=('0.0.0.0', 48391)
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
                #print(len(self.kbs))
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
def getMessage(s,q):
    while True:  
        
        try:
            data,address = s.recvfrom(65536)
            msg=bdecode(data)
            msg_type = msg.get("y", "e")
            #print(msg_type)
            #print(msg)
            if msg_type == "e":
                return

            if(msg_type == "r"):
                nodes=decode_nodes(msg["r"]["nodes"])
                #print (address)
                dealFindNodesBack(nodes,s,q)
            if(msg_type=="q"):
                if msg["q"]=="ping":
                    dealPing(msg,s,address,q)
                if msg["q"]=="find_node":
                    dealFideNodes(msg,s,address,q)
                if msg["q"]=="get_peers":
                    dealGetPeer(msg,s,address,q)
                if msg["q"]=="announce_peer":
                    dealAnnouncePeer(msg,s,address,q)
        except :
                print("error")
                pass
def dealFindNodesBack(nodes,s,q):
    for node in nodes:
        if kt.dealNode(KNode(node[0],node[1],node[2])):
            msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":random_id(),"target":random_id()}}
            adress=(node[1],node[2])
            msg2={"t":"mycode", "y":"q","q":"ping", "a":{"id":fake_node_id(node[0])}}
            #time.sleep( 0.1 )
            addQ(q,msg2,adress)
            addQ(q,msg,adress)
            
            
def dealPing(msg,s,adress,q):
    print("p")
    tid=msg['t']
    msg={"t":tid, "y":"r", "r":{"id":random_id()}}
    addQ(q,msg,adress)
def dealFideNodes(msg,s,adress,q):
    print("fn")
    tid=msg['t']
    msg={"t":tid, "y":"r", "r":{"id":random_id(),"nodes":""}}
    print(msg)
    addQ(q,msg,adress)
def dealGetPeer(msg,s,adress,q):
    tid=msg['t']
    infohash = msg["a"]["info_hash"]
    token = infohash[:2]
    infohash = proper_infohash(infohash)
    print("getPeer: "+infohash)    
    msg={"t":tid, "y":"r", "r":{"id":NodeId,"nodes":"", "token":token}}
    print(msg)
    addQ(q,msg,adress)
def dealAnnouncePeer(msg,s,adress):
    infohash = msg["a"]["info_hash"]
    infohash = proper_infohash(infohash)
    print("AnnouncePeer: "+infohash)    
    return
def addQ(q,msg,adress):
    qi=[msg,adress]
    if q.qsize()<1000:  
        q.put(qi)
def fake_node_id(node_id):
        return node_id[:-1]+random_id()[-1:]
    
def sendMSGUDP(q,s):
    a=0
    while True:
        if q.empty():
            initRoute(s)
            
        a=a+1
        qi=q.get()
        msg=qi[0]
        adress=qi[1]
        #print(adress)
        s.sendto(bencode(msg),adress)

BOOTSTRAP_NODES = (
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881)
)
def createSocekt(addr):
    clientSocket =socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    clientSocket.bind(addr)
    clientSocket.settimeout(5)
    return clientSocket
def createKtable():
    NodeId=random_id()
    kt=Ktable(NodeId)
    kb=KBucket(0,2**160)
    kt.append(kb)
    return kt
def initRoute(clientSocket):
    for r in BOOTSTRAP_NODES:
        msg={"t":"mycode", "y":"q","q":"find_node", "a":{"id":random_id(),"target":random_id()}}
        clientSocket.sendto(bencode(msg),r)
        
print("start")   
q = queue.Queue()

kt=createKtable()
clientSocket=createSocekt(LOCAL_ADDR)
initRoute(clientSocket)

_thread.start_new_thread( getMessage, (clientSocket,q, ) )
_thread.start_new_thread( sendMSGUDP, (q,clientSocket, ) )


