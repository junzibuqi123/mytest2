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
import queue
def sendgetpeers(info,nodes,msg):
    print("start getpeer-----")
    clientSocket =socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    getPeersMessage(clientSocket,info)
    for n in nodes:
        addr=(n.ip,n.port)
        clientSocket.sendto(bencode(msg),addr)
def sendgetpeers2(info,nodes,s):
    msg={"t":random_id()[:6], "y":"q","q":"get_peers", "a":{"id":random_id(),"info_hash":info}}
    for node in nodes:
        adress=(node[1],node[2])
        kt.dealNode(KNode(node[0],node[1],node[2]))
        s.sendto(bencode(msg),adress)
    
def getPeersMessage(s,info):
    while True:  
        
        try:
            data,address = s.recvfrom(1024*4)
            msg=bdecode(data)
            msg_type = msg.get("y", "e")
            #print(msg_type)
            #print(msg)
            if msg_type == "e":
                pass
            if(msg_type == "r"):
                if "token" in msg["r"]:
                    if "nodes" in msg["r"]:
                        nodes=decode_nodes(msg["r"]["nodes"])
                        sendgetpeers2(info,nodes,s)
                    if "values" in msg["r"]:
                        print(msg)
                        s.close()
                        return
                        
                    
        except ConnectionResetError:
            print("ldldldldlldldlld=======")
            
        except :
                print("error")
                #print(msg)
               # print (ExceptionType)
                raise
