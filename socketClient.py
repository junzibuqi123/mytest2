import socket
import _thread
import time
sk = socket.socket()
sk.connect(("127.0.0.1", 8999))  # 主动初始化与服务器端的连接
def sendMessage(sk):
      while True:
          time.sleep(1)
          send_data = input("输入发送内p容：")
          sk.sendall(bytes(send_data, encoding="utf8"))
def getMessage(sk):
      while True:
          accept_data = str(sk.recv(1024),encoding="utf8")
          print(accept_data)

_thread.start_new_thread( sendMessage, (sk, ) )
_thread.start_new_thread( getMessage, (sk, ) )
#sk.close()
