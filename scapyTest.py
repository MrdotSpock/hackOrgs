from scapy.all import *
import time

pk = rdpcap('test.pcap')
srcs = set()
for pkt in pk: 
    srcs.add(time.ctime(pkt.time))

print(srcs)
