import socket
import fcntl
import os
import errno
import random
import string
import pyDHE
import ssl

#create a TCP/IP socket client side
clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
server_address = ("127.0.0.1", 80)
#clientSocket.bind(server_address)
clientSocket.connect(server_address)

data = clientSocket.recv(1024)

#create the DHE keys
clientSecret = pyDHE.new(18)
key = clientSecret.negotiate(clientSocket)
print(clientSecret)

clientSocket.close()		
