import socket
import _thread
import time
import logging
logging.basicConfig(level=logging.DEBUG)
sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  # 创建socket对象
sk.bind(("127.0.0.1", 8888))
sk.listen(5) 
conn,addr = sk.accept()  # 阻塞状态，被动等待客户端的连接
def sendMessage(conn):
      while True:
          time.sleep(1)
          send_data = input("输入发送内p容：")
          conn.sendall(bytes(send_data, encoding="utf8"))
def getMessage(conn):#接收信息
      while True:
          accept_data = str(conn.recv(1024),encoding="utf8")
          logging.info(accept_data)

#_thread.start_new_thread( sendMessage, (conn, ) )
_thread.start_new_thread( getMessage, (conn, ) )   

   
