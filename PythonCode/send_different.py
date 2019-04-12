#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
import time

from multiprocessing import Process

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print 'pass 1 arguments: <destination> '
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])

    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))
    lst = []
    source =  '192.168.'
    thridByte = 0;
    fourthByte = 1;
    for i in range(1000):
        fourthByte = fourthByte + 1
        if(fourthByte==255):
            fourthByte = 1;
            thridByte = thridByte + 1;

        ipAddress =  source + str(thridByte) +'.'+str(fourthByte)
        pkt = Ether(src='00:00:00:00:01:01', dst='00:00:00:00:01:02')
        pkt = pkt / IP(src=ipAddress ,dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535))/ ""
        lst.append(pkt) 


    start = time.time()
    sendp(lst, iface=iface, verbose=False)
    print("Total Number of packages with different IP addreses: "+str(len(lst)))
    print("Time to send the packages: "+ str(time.time() - start))

if __name__ == '__main__':
    main()
