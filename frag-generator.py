#!/usr/bin/env python

from scapy.all import *

# options=[('Timestamp',(0,0))]

a = []

pkt = IP(dst="192.168.1.1")/UDP(dport=30000,sport=30000)/('A'*1440+'B'*1440+'C'*1440+'D'*1440)
check = IP(str(pkt))[UDP].chksum

frag = IP(dst="192.168.1.1", flags='MF', id=1, frag=0)/UDP(chksum=check,dport=30000,sport=30000)/('A'*1440)
a.append(frag)
send(frag)

frag = IP(dst="192.168.1.1", flags='MF', id=1, frag=181)/UDP(chksum=check,dport=30000,sport=30000)/('B'*1440)
a.append(frag)
send(frag)

frag = IP(dst="192.168.1.1", flags='MF', id=1, frag=362)/UDP(chksum=check,dport=30000,sport=30000)/('C'*1440)
a.append(frag)
send(frag)

frag = IP(dst="192.168.1.1", id=1, frag=543)/UDP(chksum=check,dport=30000,sport=30000)/('D'*1440)
a.append(frag)
send(frag)


#frag.pdfdump(layer_shift=1,filename="out.pdf")


wrpcap("temp.cap", a)


