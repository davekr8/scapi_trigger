#!/usr/bin/python

#Based on scapy-2.4.0 (run "pip install scapy" to install).
#needed tcpdump (run "apt-get install tcpdump" to install).

# features:
# read / sniff / broadcast all interfaces
# send all kinds (flavors) of wol packets to ensure a fast/reliable wake update

from scapy.all import *
from threading import Thread, Event
import time
import re, sys
import ConfigParser
import smtplib

############## CONFIG 
config = ConfigParser.RawConfigParser(allow_no_value=True)
config.optionxform = str
config.read('wol.conf')

cfg={}
for section in config.sections():
    cfg[section]={}
    for key,value in config.items(section):
        if section == "EMAIL":
            cfg[section][key]=value
        else:
            cfg[section][key.replace('-',':').lower()]=value.replace('-',':').lower()
############## CONFIG 

############## EMAIL
def sendemail(subject, message):
    
    if "EMAIL" not in cfg.keys():
        return
    
    msg = "From: %s <%s>\r\nTo: %s <%s>\r\nSubject: %s\r\n\r\n%s\r\n" % (
                cfg["EMAIL"]["txName"],
                cfg["EMAIL"]["txEmail"],
                cfg["EMAIL"]["rxName"],
                cfg["EMAIL"]["rxEmail"], subject , message )
    
    try:
        smtpObj = smtplib.SMTP("smtp.gmail.com:587")
        smtpObj.starttls()
        smtpObj.login(cfg["EMAIL"]["user"], cfg["EMAIL"]["pass"])
        problems = smtpObj.sendmail(cfg["EMAIL"]["txEmail"], cfg["EMAIL"]["rxEmail"], msg)
        if problems: print problems
        smtpObj.quit()  
    except:
        print "Error: unable to send email"
############## EMAIL 

def MAChex(mac):
    #check for lenght 12 ?
    return re.sub(r':|\.|\-',r'',mac).decode("hex")
    
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

    pending={}
    deltaTime = 60
    
    def print_packet(self, packet):
        #sniff for a predefined client->target relation in the config definition        
        if  ARP in packet and \
            packet[ARP].hwsrc in cfg['CLIENTS'].keys() and \
            packet[ARP].psrc == cfg['CLIENTS'][packet[ARP].hwsrc] and \
            packet[ARP].pdst in cfg['TARGETS'].keys() :
            
            hwsrc = packet[ARP].hwsrc
            psrc = packet[ARP].psrc
            
            hwdst = packet[ARP].hwdst
            pdst = packet[ARP].pdst
            
            mdst=cfg['TARGETS'][pdst]
            
            if pdst not in self.pending.keys() or (time.time()-self.pending[pdst]) > self.deltaTime:
                mac=MAChex(mdst)
                udpP=[0,7,9]
                sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst='255.255.255.255') / UDP(dport=udpP[2]) / Raw('\xff'*6 + mac*16),iface="eth0" , verbose=0)
                self.pending[pdst]=time.time()
                
                #send email
                subject = "ARP %s -> %s " % (psrc,pdst)
                sendemail(subject, time.strftime("%x | %X | ")+subject)
                
                #log output 
                print "%s | ARP %s [%s] -> %s [%s] : Send WOL packet to %s [%s]" %(time.strftime('%x | %X'),psrc,hwsrc,pdst,hwdst,pdst,mdst )
        
        #debug
        #if  ARP in packet: packet.show()

print "[OK] Started WOL script."                

sniffer = Sniffer()
sniffer.start()

try:
    while True:
        time.sleep(10)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join(3.0)

    if sniffer.isAlive():
        sniffer.socket.close()