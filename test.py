import socket
import _thread
import time
import logging
from bcoding import bencode, bdecode

ServerName = 'router.utorrent.com'
ServerPort = 6881
clientSocket =socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
msg={"t":"aa", "y":"q","q":"ping", "a":{"id":"abcdefghij0123456789"}}
clientSocket.sendto(bencode(msg),(ServerName,ServerPort))
modifiedmessage,serverAddress = clientSocket.recvfrom(2048)
print (bdecode(modifiedmessage))
clientSocket.close()
