pk = rdpcap('test.pcap')
srcs = set()
for pkt in pk: 
         if Dot11 in pkt:
             srcs.add(pkt[Dot11].addr1)
