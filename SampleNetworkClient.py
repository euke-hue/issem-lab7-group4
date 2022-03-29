
import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from Incubator import infinc
import time
import math
import socket
import fcntl
import os
import errno
import random
import string
import rsa 
from decouple import config # used for env file

class SimpleNetworkClient :
    def __init__(self, port1, port2) :
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infPort = port1
        self.incPort = port2

        self.__infToken = None
        self.__incToken = None

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)
        with open ('pubkey.pem', 'rb') as p:
            self.publickey = rsa.PublicKey.load_pkcs1(p.read())
        with open ('privkey.pem', 'rb') as p:
            self.privatekey = rsa.PrivateKey.load_pkcs1(p.read())

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def getTemperatureFromPort(self, p, tok) :
        #the token that is passed in from updateInf or updateInc should be from the token variables
        token = tok +";"+"GET_TEMP"
        encoded_token = token.encode("utf-8")
        encryptedtoken = rsa.encrypt(encoded_token, self.publickey)
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.sendto(encryptedtoken, ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        #the mssage you receive SHOULD just be the inf of inc temp
        m = msg.decode("utf-8").strip()
        print(m,"tempreceived!!!")
        return (float(m))

    def authenticate(self, p) :
        #send the encrypted password
        password = "AUTH"+" "+config('SECRET_KEY')
        encoded_password = password.encode("utf-8")
        encryptedpassword = rsa.encrypt(encoded_password, self.publickey)
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.sendto(encryptedpassword, ("127.0.0.1", p))
        #receive the token here
        msg, addr = s.recvfrom(1024)
        #decrypt the received token
        decrypt_msg = rsa.decrypt(msg, self.privatekey)
        #decode the token
        decoded_msg = decrypt_msg.decode("utf-8")
        #strip the token and return it so it can get stored in the self.infToken or self.incToken
        print(decoded_msg,"dcoded!!")
        return decoded_msg.strip()

    def updateInfTemp(self, frame) :
        self.updateTime()
        if self.__infToken is None : #not yet authenticated
            self.__infToken = self.authenticate(self.infPort)

        self.infTemps.append(self.getTemperatureFromPort(self.infPort, self.__infToken)-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        if self.__incToken is None : #not yet authenticated
            self.__incToken = self.authenticate(self.incPort)

        self.incTemps.append(self.getTemperatureFromPort(self.incPort, self.__incToken)-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,
