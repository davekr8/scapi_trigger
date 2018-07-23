#!/usr/bin/python

#Based on scapy-2.4.0 (run "pip install scapy" to install).
#needed tcpdump (run "apt-get install tcpdump" to install).

from scapy.all import *
from threading import Thread, Event
from time import sleep
import re
import sys

#MACsrcs
MACsrcs=[ "a4:d1:8c:cb:b6:b6",\
    ]
    
#IPdsts
IPdsts=[ "192.168.2.99",\
    ]

MACdst="e0:d5:5e:2e:6f:9e"

def MAChex(mac):
    #check for lenght 12 ?
    return re.sub(r':|\.|\-',r'',mac).decode("hex")


#see https://github.com/tykling/tykwol/blob/master/tykwol.py
    
class Sniffer(Thread):
    def  __init__(self, interface="eth0"):
        super(Sniffer,self).__init__()

        self.daemon = True

        self.socket = None
        self.interface = interface
        self.stop_sniffer = Event()

    def run(self):
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="arp"
        )

        sniff(
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer,
            store=0
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super(Sniffer,self).join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def pingNwake(self,pdst):        
        packet = IP(dst=pdst, ttl=5)/ICMP()
        
        print "try ping on "+ pdst
        reply = sr1(packet, timeout=5, verbose=0)
        
        
        if not reply:
            print "Timeout waiting for %s" % packet[IP].dst
             
            mac=MAChex(MACdst)
            udpP=[0,7,9] 
            
            print "send wol on " + MACdst 
            sendp(Ether(dst='ff:ff:ff:ff:ff:ff') /IP(dst='255.255.255.255') /UDP(dport=udpP[2]) /Raw('\xff'*6 + mac*16),iface="eth0" , verbose=0)
            
            #alternatives
            
            #sendp(Ether(type=int('0842', 16), dst='ff:ff:ff:ff:ff:ff') / Raw('\xff'*6 + mac*16), iface="eth0")
            #sendp([Ether(dst=self.ETH_BROADCAST) / IP(dst='255.255.255.255') / UDP(sport=32767, dport=9)/ Raw(load=self.wol_payload)], iface=self.intf)
             
        else:
            print reply.dst, "is online"
        
        
    def print_packet(self, packet):
        if  ARP in packet and \
            packet[ARP].op == 1 and \
            packet[ARP].hwsrc in MACsrcs and \
            packet[ARP].pdst in IPdsts:
            
            pdst = packet[ARP].pdst
            
            #single call
            self.pingNwake(pdst)
            
            #muli-threaded call (async)
            #Thread(target=self.pingNwake, args=[pdst]).start()


sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join(2.0)

    if sniffer.isAlive():
        sniffer.socket.close()