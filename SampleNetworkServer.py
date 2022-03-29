
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

#def servergenerateKeys():
#    print("this ran")
#    (publickey, privatekey) = rsa.newkeys(2048)
#    with open ('pubkey.pem', 'wb') as p:
#        p.write(publickey.save_pkcs1('PEM'))
#    with open ('privkey.pem', 'wb') as p:
#        p.write(privatekey.save_pkcs1('PEM'))


class SmartNetworkThermometer (threading.Thread) :
    open_cmds = ["AUTH", "LOGOUT"]
    prot_cmds = ["SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP"]

    def __init__ (self, source, updatePeriod, port) :
        threading.Thread.__init__(self, daemon = True) 
        #set daemon to be true, so it doesn't block program from exiting
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()
        self.__tokens = []
        
        with open ('pubkey.pem', 'rb') as p:
            self.publickey = rsa.PublicKey.load_pkcs1(p.read())
        with open ('privkey.pem', 'rb') as p:
            self.privatekey = rsa.PrivateKey.load_pkcs1(p.read())
        
        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"

    def setSource(self, source) :
        self.source = source

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod 

    def setDegreeUnit(self, s) :
        self.deg = s
        if self.deg not in ["F", "K", "C"] :
            self.deg = "K"

    def updateTemperature(self) :
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self) :
        if self.deg == "C" :
            return self.curTemperature - 273
        if self.deg == "F" :
            return (self.curTemperature - 273) * 9 / 5 + 32

        return self.curTemperature

    def processCommands(self, msg, addr) :
        
        cmds = msg.split(';')
        for c in cmds :
            cs = c.split(' ')
            if len(cs) == 2 : #should be either AUTH or LOGOUT
                if cs[0] == "AUTH":
                    if cs[1] == config('SECRET_KEY') :
                            if len(self.__tokens) < 1:
                                self.__tokens.append(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)))
                                encoded_token = self.__tokens[-1].encode("utf-8")
                                encrypted_token = rsa.encrypt(encoded_token, self.publickey)
                                self.serverSocket.sendto(encrypted_token, addr)
                            else:
                                pass
                        
                        
                        #encrypt the token here then encode and then send it
           
                        #print (self.tokens[-1])
                elif cs[0] == "LOGOUT":
                    if cs[1] in self.tokens :
                        self.__tokens.remove(cs[1])
                else : #unknown command
                    self.serverSocket.sendto(b"Invalid Command\n", addr)
            elif c == "SET_DEGF" :
                self.deg = "F"
            elif c == "SET_DEGC" :
                self.deg = "C"
            elif c == "SET_DEGK" :
                self.deg = "K"
            elif c == "GET_TEMP" :
                self.serverSocket.sendto(b"%f\n" % self.getTemperature(), addr)
            elif c == "UPDATE_TEMP" :
                self.updateTemperature()
            elif c :
                self.serverSocket.sendto(b"Invalid Command\n", addr)


    def run(self) : #the running function
        #servergenerateKeys()
        while True : 
            try :

                msg, addr = self.serverSocket.recvfrom(1024)
                if len(msg) > 22:
                    print("this worked")
                    decrypted_msg = rsa.decrypt(msg, self.privatekey)
                    decoded_msg = decrypted_msg.decode("utf-8").strip()
                    print(decoded_msg)
                    cmds = decoded_msg.split(' ')

                    if len(cmds) == 1 : # protected commands case
                        print("thiswastoken")
                        semi = decoded_msg.find(';')
                        if semi != -1 : #if we found the semicolon
                            #print (msg)
                            if decoded_msg[:semi] in self.__tokens : #if its a valid token
                                self.processCommands(decoded_msg[semi+1:], addr)
                            else :
                                self.serverSocket.sendto(b"Bad Token\n", addr)
                        else :
                                self.serverSocket.sendto(b"Bad Command\n", addr)
                    elif len(cmds) == 2 :
                        print("this was auth")
                        if cmds[0] in self.open_cmds : #if its AUTH or LOGOUT
                            self.processCommands(decoded_msg, addr) 
                        else :
                            self.serverSocket.sendto(b"Authenticate First\n", addr)
                    else :
                        # otherwise bad command
                        self.serverSocket.sendto(b"Bad Command\n", addr)

                else:                
                    msg = msg.decode("utf-8").strip()
                    cmds = msg.split(' ')
                    if len(cmds) == 1 : # protected commands case
                        semi = msg.find(';')
                        if semi != -1 : #if we found the semicolon
                            #print (msg)
                            if msg[:semi] in self.__tokens : #if its a valid token
                                self.processCommands(msg[semi+1:], addr)
                            else :
                                self.serverSocket.sendto(b"Bad Token\n", addr)
                        else :
                                self.serverSocket.sendto(b"Bad Command\n", addr)
                    elif len(cmds) == 2 :
                        if cmds[0] in self.open_cmds : #if its AUTH or LOGOUT
                            self.processCommands(msg, addr) 
                        else :
                            self.serverSocket.sendto(b"Authenticate First\n", addr)
                    else :
                        # otherwise bad command
                        self.serverSocket.sendto(b"Bad Command\n", addr)
    
            except IOError as e :
                if e.errno == errno.EWOULDBLOCK :
                    #do nothing
                    pass
                else :
                    #do nothing for now
                    pass
                msg = ""

 

            self.updateTemperature()
            time.sleep(self.updatePeriod)


class SimpleClient :
    def __init__(self, therm1, therm2) :
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
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

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


    def updateInfTemp(self, frame) :
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature()-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature()-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,
