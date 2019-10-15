dataFile = open("./AnalyticData/data.txt", "w")
pkts = rdpcap("test.pcap")
src_to_dest = dict()

for pkt in pkts:
	if pkt[Dot11].type == 2:
		if pkt[Dot11].addr3 in src_to_dest:
			src_to_dest.get(pkt[Dot11].addr3).append(pkt[Dot11].addr1)
		else:
			src_to_dest[pkt[Dot11].addr3] = [pkt[Dot11].addr1]

dataFile.write(str(src_to_dest))

for src in src_to_dest.keys():
	print(src)
	for dest in src_to_dest[src]:
		print("\t" + str(dest))
		# print(dest)
	print()
