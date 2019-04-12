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

def send_multi(pkt, iface, num):
    sendp(pkt, iface=iface, verbose=False, count=num)

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<numperOfPackers per process (10 processes)>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    numperOfPackers =  int(sys.argv[2])
    print(numperOfPackers)
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))


    pckList = []
    for i in range(0, 10):
        pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:01:02')
        dstdPort = 1230
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535))/ "" 
        pckList.append(pkt)
        dstdPort+=1
    

    start = time.time()
    proc = []

    for i in range(0, 10):
        p = Process(target=send_multi, args=(pkt,iface,numperOfPackers,))
        proc.append(p)
        p.start()


    print(len(proc))
    for i in proc:
        i.join()

    #sendp(pkt, iface=iface, verbose=False, count=500)
    print(time.time() - start)

if __name__ == '__main__':
    main()
