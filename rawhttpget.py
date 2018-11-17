#! /usr/bin/env python
__author__ = 'phd_208'
from urlparse import urlparse
import socket
import sys
import threading
import time
import random
import struct
from datetime import datetime
import Queue # threadsafe data structure :D
####################################


#Global Variables
TIMEOUT_HANDSHAKE = 4 # seconds.
CONNECTION_CLOSED = False
FILE_TRANSFER_COMPLETE = False
GET_REQ_DONE = False
REQUEST_CONNECTION_CLOSE = False
LOCK_ACK = threading.RLock()

# Send thread after a connnection is established.
# Handles sending data as well as graceful closure
def sendThread(sendSocket, tcpTup, getData):
    global CONNECTION_CLOSED
    global REQUEST_CONNECTION_CLOSE
    nextSeqNum = tcpTup.nextSeqNum
    tcpTup.nextSeqNum = (tcpTup.nextSeqNum + len(getData)) & 0xFFFFFFFF
    ip_id = 15104
    # sending a syn-ack and a get request
    while not CONNECTION_CLOSED:
        if tcpTup.recvWindowSize < 50:
            time.sleep(0.5)
            with LOCK_ACK:
                request_connection_close = REQUEST_CONNECTION_CLOSE
            continue
        if GET_REQ_DONE:
            break
        tcp = TCPHeader()
        tcpHeader = tcp.makeTCPHeader(tcpTup.sourcePort,
            tcpTup.destinationPort, nextSeqNum,
            tcpTup.ackNum, 0, 1, 0, tcpTup.windowSize,
            tcpTup.sourceIP, tcpTup.destinationIP, getData)
        ip = IPHeader()
        ip_id = (ip_id + 1) & 0xFFFF
        ipHeader = ip.makeIPHeader(tcpTup.sourceIP,
            tcpTup.destinationIP, ip_id)
        pkt = ipHeader + tcpHeader + getData
        # send syn
        sendSocket.sendto(pkt,
            (tcpTup.destinationIP, tcpTup.destinationPort))
        time.sleep(0.3)
    # regular stuff. not fin
    getData = ""
    request_connection_close = REQUEST_CONNECTION_CLOSE
    while not request_connection_close:
        if tcpTup.recvWindowSize < 50: # recv window size. don't overwhelm the reciever
            time.sleep(0.5)
            with LOCK_ACK:
                request_connection_close = REQUEST_CONNECTION_CLOSE
            continue
        with LOCK_ACK:
            ackNumToSend = tcpTup.ackNum
        tcp = TCPHeader()
        tcpHeader = tcp.makeTCPHeader(tcpTup.sourcePort,
            tcpTup.destinationPort, tcpTup.nextSeqNum,
            ackNumToSend, 0, 1, tcpTup.finBit, tcpTup.windowSize,
            tcpTup.sourceIP, tcpTup.destinationIP, getData)
        ip = IPHeader()
        ip_id = (ip_id + 1) & 0xFFFF
        ipHeader = ip.makeIPHeader(tcpTup.sourceIP,
            tcpTup.destinationIP, ip_id)
        pkt = ipHeader + tcpHeader + getData
        # send syn
        sendSocket.sendto(pkt,
            (tcpTup.destinationIP, tcpTup.destinationPort))
        time.sleep(0.05)
        with LOCK_ACK:
            request_connection_close = REQUEST_CONNECTION_CLOSE
    #print "Going for a graceful closure"
    # graceful closure, send mult fins.
    tcpTup.nextSeqNum = (tcpTup.nextSeqNum + 1) & 0xFFFFFFFF
    for i in range(6):
        with LOCK_ACK:
            ackNumToSend = tcpTup.ackNum
        tcp = TCPHeader()
        tcpHeader = tcp.makeTCPHeader(tcpTup.sourcePort,
            tcpTup.destinationPort, tcpTup.nextSeqNum,
            ackNumToSend, 0, 1, tcpTup.finBit, tcpTup.windowSize,
            tcpTup.sourceIP, tcpTup.destinationIP, getData)
        ip = IPHeader()
        ip_id = (ip_id + 1) & 0xFFFF
        ipHeader = ip.makeIPHeader(tcpTup.sourceIP,
            tcpTup.destinationIP, ip_id)
        pkt = ipHeader + tcpHeader + getData
        # send syn
        sendSocket.sendto(pkt,
            (tcpTup.destinationIP, tcpTup.destinationPort))
    CONNECTION_CLOSED = True
    sendSocket.close()
    return

# Reciever thread after a connection is established 
def recvThread2(recvSocket, tcpTup, pktQueue, fname): # ip check thread
    try:
        recvThread(recvSocket, tcpTup, pktQueue, fname) # ip check thread
    except:
        with LOCK_ACK:
            global CONNECTION_CLOSED
            global GET_REQ_DONE
            global REQUEST_CONNECTION_CLOSE
            CONNECTION_CLOSED = True
            GET_REQ_DONE = True
            REQUEST_CONNECTION_CLOSE = True
        print "Timeout."
        exit()

# note: windowSize = cwnd * MSS. the recieverwindow size is done is sender thread
def recvThread(recvSocket, tcpTup, pktQueue, fname): # ip check thread
    global CONNECTION_CLOSED
    global GET_REQ_DONE
    global REQUEST_CONNECTION_CLOSE
    outputData = []
    recvSocket.settimeout(60)
    t1 = datetime.now() # packet lost timeout.
    t3 = t1 # connection close timeout
    while not CONNECTION_CLOSED:
#        try:
            recievedData = recvSocket.recvfrom(65536)
            # process packet!
            t2 = datetime.now()
            t4 = t2
            if (t4 - t3).seconds >= 180:
                x = 2/0 # throw exception, for timeout  
            if (t2 - t1).seconds >= 10: # 10 sec instead of the 60 since 60 is too long.
                with LOCK_ACK:
                    tcpTup.windowSize = 1420
                t1 = datetime.now()
            if recievedData[1][0] == tcpTup.destinationIP: # check source ip
                tcpH, ipH, httpData = getPacketFromData(recievedData[0],
                    tcpTup) # validate packet and get it.
                #print "Recv"
                if tcpH is not None and ipH is not None:
                    # validate seqNum, AckNum, fin, syn, ack
                    #print tcpH.seqNum, tcpTup.ackNum
                    if tcpH.ackNum == tcpTup.nextSeqNum and tcpH.syn == 0 and tcpH.ack==1:
                        #print tcpH.seqNum
                        if tcpTup.ackNum == tcpH.seqNum:
                            tcpTup.recvWindowSize = tcpH.windowSize
                            with LOCK_ACK: # increment expected Ack number and the window size
                                tcpTup.ackNum = (tcpH.seqNum + len(httpData)) & 0xFFFFFFFF
                                tcpTup.windowSize = min(tcpTup.windowSize + 1420, 60000)
                            outputData.append(httpData) # buffer data instead of storing to a temp file
                            t1 = datetime.now()
                            t3 = t1
                            #print len(httpData)
                            if tcpH.fin == 1: # graceful closure
                                with LOCK_ACK:
                                    tcpTup.finBit = 1
                                    REQUEST_CONNECTION_CLOSE = True
                                break
                        elif tcpH.seqNum > tcpTup.ackNum: # we half the cwnd
                            with LOCK_ACK: #half it.
                                tcpTup.windowSize = max(tcpTup.windowSize/2 , 1420)
                            
                        GET_REQ_DONE = True


#        except:
#            print "testingsd"
    recvSocket.close()
    #print outputData
    # only handle 200n
    out2 = (''.join(outputData))
    g = out2.split("\r\n\r\n")
    if (g[0].find('Transfer-Encoding: chunked')) == -1:
        out = "".join(g[1:])
    else:
        out = "".join(("".join(g[1:])).split('\r\n')[1::2])
    with open(fname, 'w') as f:
        f.write(out)
        f.flush()
    return


def packetParseThread(): #tcp check thread.

    return


def fileWriterThread():

    return

#calculate tcp checksum
def getCheckSum(dat):
    dataLen = len(dat)
    i = 0
    chkSum = 0
    while i < dataLen:
        if i+1 == dataLen:
            chkSum += (0 << 8) | ord(dat[i]) # wireshark+silvermoon
        else:
            chkSum += (ord(dat[i + 1]) << 8) | ord(dat[i])  # wireshark+silvermoon
        i += 2
    chkSumCarry = chkSum >> 16
    chkSum = chkSum & 0xffff
    chkSum += chkSumCarry
    chkSum = ~chkSum & 0xffff
    return chkSum

#validate the checksum of tcp and ip headers
def validateCheckSum(headerchkSum, data):
    # data is in network byte order. checksum is in host byte order
    # so we use reverse
    dataLen = len(data)
    i = 0
    chkSum = 0
    while i < dataLen:
        if i+1 == dataLen:
            chkSum += (ord(data[i]) << 8)  # wireshark+silvermoon
            #trying reverse now.
            #chkSum += ord(data[i])
        else:
            chkSum += (ord(data[i]) << 8) | ord(data[i + 1])  # wireshark+silvermoon
        i += 2
    chkSumCarry = (chkSum >> 16)
    chkSum = (chkSum & 0xffff)
    chkSum += chkSumCarry
    chkSumCarry = (chkSum >> 16)
    chkSum = (chkSum & 0xffff)
    chkSum += chkSumCarry
    chkSumCarry = (chkSum >> 16)
    chkSum = (chkSum & 0xffff)
    chkSum += chkSumCarry
    #print hex(chkSum), hex(headerchkSum),  bin(chkSum), bin(headerchkSum)
    if (chkSum | headerchkSum) == 0xFFFF:
        return True
    #print bin(chkSum), bin(headerchkSum)
    return False


class GlobVar():  # global variables class. easier to pass an instance.
    def __init__(self):
        self.destIP = ""
        self.srcIP = ""
        self.cwnd = 0

# a few global variables
class GlobTCPVar():
    def __init__(self, sourceIP, destinationIP, sourcePort, destinationPort):
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.nextSeqNum = random.randint(9000, 100000000)
        self.startSeqNum = self.nextSeqNum
        self.cwnd = 1
        self.windowSize = 1420
        self.recvWindowSize = 10000
        self.ackNum = 0
        self.finBit = 0

#class to make tcp headers and get them from raw data
class TCPHeader():

    def __init__(self):
        self.srcPort = 0  # later
        self.destPort = 0  # later
        self.seqNum = 0  # later
        self.ackNum = 0  # later
        self.dataOffset = 6
        self.reserved = 0
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.windowSize = 1420
        self.checksum = 0
        self.urgentPtr = 0
        self.fieldLenDict = {"source port": 16, "destination port": 16,
            "seq num": 32, "ack num": 32, "offset": 4, "reserved": 4, "cwr": 1,
            "ece": 1, "urg": 1, "ack": 1, "psh": 1, "rst": 1, "syn": 1,
            "fin": 1, "window size": 16, "checksum": 16, "urgent pointer": 16}

    def makeTCPHeader(self, srcPort, destPort, seqNum, ackNum,syn, ack, fin, windowSize, sourceIP, destinationIP, userData):
        self.srcPort = srcPort
        self.destPort = destPort
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.syn = syn
        self.ack = ack
        self.fin = fin
        self.windowSize = windowSize  #socket.htons(windowSize)
        tcp_data_off_some_reserved = (self.dataOffset << 4) + self.reserved
        tcp_flgs_some_reserved = (self.cwr << 7) + (self.ece << 6) + \
            (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + \
            (self.rst << 2) + (self.syn << 1) + self.fin
        # L is for 4-byte integers. H is for 2 byte ints. B is for 1 byte ints.
        tcpHeader = struct.pack('!HHLLBBHHHBBH', self.srcPort, self.destPort,
            self.seqNum, self.ackNum, tcp_data_off_some_reserved,
            tcp_flgs_some_reserved, self.windowSize, self.checksum,
            self.urgentPtr,2,4,1420) #last 3: option tye, option lengthu, val
        # created a basic header. calculate length
        tcpLen = len(tcpHeader) + len(userData)
        prot = socket.IPPROTO_TCP
        resv = 0
        srcIP = socket.inet_aton(sourceIP)
        destIP = socket.inet_aton(destinationIP)
        # create a psuedo header to calculate checksum
        psuedoHeader = struct.pack('!4s4sBBH', srcIP, destIP,
            resv, prot, tcpLen)
        chkSum = getCheckSum(psuedoHeader + tcpHeader + userData)

        # recreate header and add checksum
        tcpHeader = struct.pack('!HHLLBBH', self.srcPort, self.destPort,
            self.seqNum, self.ackNum, tcp_data_off_some_reserved,
            tcp_flgs_some_reserved, self.windowSize) + struct.pack('H',chkSum) + struct.pack('!HBBH',self.urgentPtr,2,4,1420)
        return tcpHeader

    def parseDataMakeClass(self, tcph, tcpTup, recvData):
        #print tcph
        self.srcPort = tcph[0]
        self.destPort = tcph[1]

        if self.srcPort != tcpTup.destinationPort or self.destPort != tcpTup.sourcePort:
            #print "Port Mismatch.",self.srcPort, tcpTup.destinationPort, self.destPort, tcpTup.sourcePort
            return False

        # check these two later
        self.seqNum = tcph[2]
        self.ackNum = tcph[3]
        #print self.seqNum
        #print self.ackNum

        tcp_data_off_some_reserved = tcph[4]
        self.dataOffset = tcp_data_off_some_reserved >> 4
        self.reserved = tcp_data_off_some_reserved & 0xF

        tcp_flgs_some_reserved = tcph[5]
        self.cwr = (tcp_flgs_some_reserved >> 7) & 0x1
        self.ece = (tcp_flgs_some_reserved >> 6) & 0x1
        self.urg = (tcp_flgs_some_reserved >> 5) & 0x1
        self.ack = (tcp_flgs_some_reserved >> 4) & 0x1
        self.psh = (tcp_flgs_some_reserved >> 3) & 0x1
        self.rst = (tcp_flgs_some_reserved >> 2) & 0x1
        self.syn = (tcp_flgs_some_reserved >> 1) & 0x1
        self.fin = tcp_flgs_some_reserved & 0x1

        self.windowSize = tcph[6]

        # important
        self.checksum = tcph[7]
        #check sum
        tcpLen = len(recvData)
        prot = socket.IPPROTO_TCP
        resv = 0
        srcIP = socket.inet_aton(tcpTup.destinationIP)
        destIP = socket.inet_aton(tcpTup.sourceIP)
        psuedoHeader = struct.pack('!4s4sBBH', srcIP, destIP,
            resv, prot, tcpLen)
        if not validateCheckSum(self.checksum, psuedoHeader+recvData[0:16]+recvData[18:]):
            #print "TCP checksum failed"
            return False
        # not used
        self.urgentPtr = tcph[8]
        #print "Something right"
        return True


class IPHeader():

    def __init__(self):
        self.version = 4
        self.headerLength = 5
        self.serviceType = 0
        self.totLen = 0  # will change it later
        self.flX = 0
        self.flD = 0
        self.flM = 0
        self.offset = 0
        self.ttl = 64
        self.protocol = socket.IPPROTO_TCP
        self.headerchecksum = 0
        self.id = 0  # later
        self.srcIP = 0  # later
        self.destIP = 0  # later

    def makeIPHeader(self, source_addr, dest_addr, ip_id=15104):
        self.id = ip_id
        self.srcIP = socket.inet_aton(source_addr)
        self.destIP = socket.inet_aton(dest_addr)
        #put header checksum and totlen
        ip_ver_hl = (self.version << 4) + self.headerLength # joined 2 nibbles
        ip_flgs_off = (self.flX << 15) + (self.flD << 14) + (self.flM << 13) + \
            self.offset
        # ! is for network byte order, B is for Bytes, H is for 2-Bytes
        ipHeader = struct.pack('!BBHHHBBH4s4s', ip_ver_hl, self.serviceType,
            self.totLen, self.id, ip_flgs_off, self.ttl, self.protocol,
            self.headerchecksum, self.srcIP, self.destIP)
        return ipHeader

    def parseDataMakeClass(self, ipH, tcpTup):
        # we don't handle packets with M flag, or with off set
        # version and header
        ip_ver_hl = ipH[0]
        self.headerLength = ip_ver_hl & 0xF  # can't check it right now.

        self.version = ip_ver_hl >> 4
        if self.version != 4:
            #print "Wrong version of IP"
            return False

        self.serviceType = ipH[1]
        self.totLen = ipH[2]
        self.id = ipH[3]

        # not looking for offset and stuff
        ip_flgs_off = ipH[4]
        self.offset = ((ip_flgs_off << 3) & 0xFFFF) >> 3
        self.flX = (ip_flgs_off >> 15)
        self.flD = (ip_flgs_off >> 14) & 0x1
        self.flM = (ip_flgs_off >> 13) & 0x1
        if self.offset != 0 or self.flM == 1:
            #print "Offset in IP header"
            return False

        self.ttl = ipH[5]
        self.protocol = ipH[6]
        if self.protocol != socket.IPPROTO_TCP:
            return False
        self.headerchecksum = ipH[7]

        self.srcIP = socket.inet_ntoa(ipH[8])
        self.destIP = socket.inet_ntoa(ipH[9])

        # check src and dest ip
        if self.srcIP != tcpTup.destinationIP or self.destIP != tcpTup.sourceIP:
            return False

        # validate checksum
        tempData = struct.pack('!BBHHHBB4s4s', ipH[0], ipH[1],
            ipH[2], ipH[3], ipH[4], ipH[5], ipH[6],
            ipH[8], ipH[9])

        if not validateCheckSum(self.headerchecksum, tempData):
            return False

        return True

####################################


def makeGet(hostname, filepath):
    getrequest = 'GET ' + filepath + ' HTTP/1.1\r\n' +\
             'Accept: */*\r\n' +\
             'Host: ' + hostname + '\r\n' +\
             'Connection: Keep-Alive\r\n\r\n'
             #'User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; ' +\
             #'en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 ' +\
             #'(.NET CLR 3.5.30729)\r\n'
    return getrequest


def getTargetURL(args):
    if len(args) != 2:
        exit()
    return args[1]


def getTargetFilename(targetURL):
    try:
        parsedurl = urlparse(targetURL)
        #print parsedurl
    except:
        print "Usage: ./rawhttpget [URL]"
        exit()
    filename = "index.html"
    filepath = parsedurl.path
    hostnameWithPort = parsedurl.netloc
    destinationPort = 80
    if len(hostnameWithPort.split(':')) > 1:
        destinationPort = int(hostnameWithPort.split(':')[1])
    hostname = hostnameWithPort.split(':')[0]
    if len(parsedurl.path) == 0:
        return filename, hostname, filepath, destinationPort
    fname = parsedurl.path.split('/')[-1]
    if len(fname) == 0:
        return filename, hostname, filepath, destinationPort
    return fname, hostname, filepath, destinationPort


def createSendSocket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
            socket.IPPROTO_RAW)
    except:
        print 'Unable to create a send socket.'
        exit()
    return sock


def createReceiveSocket(HOST):
    try:
        # socket.SOCK_STREAM,socket.IPPROTO_IP. stream needs connection
        # the following is the only possible option.We cant use ipproto_ip
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
            socket.IPPROTO_TCP)
        myPort = random.randint(6000, 62000)
        #print sock.getsockname()
        #myPort = sock.getsockname()[1]
        #sock.listen(20) # buffer 20 requests
    except:
        print 'Unable to create a receive socket.'
        exit()
    return sock, myPort

#function to validate ip header
def validateAndGetIPHeader(iph, recievedData, tcpTup):
    ipHeader = None
    ipHeaderArray = struct.unpack('!BBHHHBBH4s4s', iph)
    ipHeader = IPHeader()
    if not (ipHeader.parseDataMakeClass(ipHeaderArray, tcpTup)):
        #print "malformed Ip header"
        return None
    if ipHeader.totLen != len(recievedData):
        #print "length mismatch Ip header"
        return None
    return ipHeader

# functoin to validate tcp header
def validateAndGetTCPHeader(tcph, recvDataNoIpHead, tcpTup):
    tcpHeader = None
    tcpHeaderArray = struct.unpack('!HHLLBBHHH', tcph)
    tcpHeader = TCPHeader()
    if not tcpHeader.parseDataMakeClass(tcpHeaderArray, tcpTup, recvDataNoIpHead):
        #print "malformed tcp header"
        return None
    return tcpHeader

# if all is validated then return the data
def getPacketFromData(recievedData, tcpTup):
    tcpHeader = None
    ipHeader = None
    if recievedData is None:
        #print "Nothing"
        return tcpHeader, ipHeader
    if len(recievedData) < 40:
        #print "Darn it"
        return tcpHeader, ipHeader
    # check ip header stuff
    iph = recievedData[0:20]
    try:
        ipHeader = validateAndGetIPHeader(iph, recievedData, tcpTup)
    except:
        return None, None, None
    if ipHeader is None:
        return None, None, None
    #print "sdmsd"
    # check tcp header stuff
    try:
        x = ipHeader.headerLength * 4
        recievedDataNoIp = recievedData[x:]
        tcph = recievedData[x:x + 20]
        tcpHeader = validateAndGetTCPHeader(tcph, recievedDataNoIp, tcpTup)
    except:
    #    print "samosasdse"
        return None, None, None
    if tcpHeader is None:
    #    print "soonn ofa a"
        return None, None, None
    y = tcpHeader.dataOffset * 4
    dat = recievedData[x + y:]

    return tcpHeader, ipHeader, dat


def performTCPHandshake(sendSocket, recvSocket, globalTCPVar):
    global TIMEOUT_HANDSHAKE
    testData = ""
    tcp = TCPHeader()
    tcpHeader = tcp.makeTCPHeader(globalTCPVar.sourcePort,
        globalTCPVar.destinationPort, globalTCPVar.nextSeqNum,
        globalTCPVar.ackNum, 1, 0, 0, globalTCPVar.windowSize,
        globalTCPVar.sourceIP, globalTCPVar.destinationIP, testData)
    globalTCPVar.nextSeqNum += 1
    ip = IPHeader()
    ipHeader = ip.makeIPHeader(globalTCPVar.sourceIP,
        globalTCPVar.destinationIP, 15104)
    pkt = ipHeader + tcpHeader + testData
    # send syn
    sendSocket.sendto(pkt,
        (globalTCPVar.destinationIP, globalTCPVar.destinationPort))
    syn_ack_found = False
    recvSocket.settimeout(TIMEOUT_HANDSHAKE)
    t1 = datetime.now()
    # get a syn-ack
    while not syn_ack_found:
        try:
            recievedData = recvSocket.recvfrom(65536)
            # process packet!
            if recievedData[1][0] == globalTCPVar.destinationIP:
                tcpH, ipH, httpData = getPacketFromData(recievedData[0],
                    globalTCPVar)
                if tcpH is not None and ipH is not None:
                    # validate seqNum, AckNum, fin, syn, ack
                    if tcpH.ackNum == globalTCPVar.nextSeqNum and tcpH.syn == 1 and tcpH.ack==1 and tcpH.fin == 0:
                        syn_ack_found = True
            # check for timeout.
            t2 = datetime.now()
            if (t2 - t1).seconds > TIMEOUT_HANDSHAKE:
                TIMEOUT_HANDSHAKE *= 2
                sendSocket.sendto(pkt,
                    (globalTCPVar.destinationIP, globalTCPVar.destinationPort))
                t1 = datetime.now()
                if TIMEOUT_HANDSHAKE > 10:
                    print "No response from the server after 3 tries."
                    exit()
        except:
            TIMEOUT_HANDSHAKE *= 2
            sendSocket.sendto(pkt,
                (globalTCPVar.destinationIP, globalTCPVar.destinationPort))
            t1 = datetime.now()
            if TIMEOUT_HANDSHAKE > 10:
                print "No response from the server after 3 tries."
                exit()
    #
    globalTCPVar.nextSeqNum = tcpH.ackNum
    globalTCPVar.ackNum = (tcpH.seqNum + 1) & 0xFFFFFFFF


def main(args):
    targetURL = getTargetURL(args)
    # get hostname
    try:
        filename, hostname, filepath,destinationPort = getTargetFilename(targetURL)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53)) # dns query to get our local ip address
        sourceIP = s.getsockname()[0]
        s.close()
        #sourceIP = socket.gethostbyname(socket.gethostname())
        destinationIP = socket.gethostbyname(hostname)
    except:
        print "Unable to resolve destination host"
        print "Usage: ./rawhttpget [URL]"
        exit()
    #print sourceIP, hostname, destinationIP
    # create a send socket
    sendSocket = createSendSocket()
    recvSocket, sourcePort = createReceiveSocket(sourceIP)
    globalTCPVar = GlobTCPVar(sourceIP, destinationIP,
        sourcePort, destinationPort)
    # handshake
    performTCPHandshake(sendSocket, recvSocket, globalTCPVar)
    pktQueue = Queue.Queue()
#    if filename == "index.html":
#        filepath = "/index.html"
    getData = makeGet(hostname, filepath)
    # send ack and a get request. Let's outsource some stuff to GIL as well
    t_send = threading.Thread(target=sendThread,
        args=(sendSocket, globalTCPVar, getData))
    t_recv = threading.Thread(target=recvThread2,
        args=(recvSocket, globalTCPVar, pktQueue, filename))

    t_send.daemon = True
    t_recv.daemon = True

    t_recv.start()
    t_send.start()

    t_send.join()
    t_recv.join()

    #time.sleep(5)

if __name__ == "__main__":
    main(sys.argv)

