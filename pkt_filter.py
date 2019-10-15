# Functions
def printDict(dict):
	for src in dict.keys():
		print(src)
		for dest in dict[src]:
			print("\t" + str(dest))
		print()

# Main
dataFile = open("./AnalyticData/data.txt", "w")
pkts = rdpcap("test.pcap")
src_to_dest = dict()

for pkt in pkts:
	if pkt[Dot11].type == 2 and pkt[Dot11].subtype == 8:
		src = ""
		dest = ""
		if pkt[Dot11].FCfield & 0x1: #From device to router
			src = pkt[Dot11].addr1
			dest = pkt[Dot11].addr3
		elif pkt[Dot11].FCfield & 0x2:	#From router to device
			src = pkt[Dot11].addr3
			dest = pkt[Dot11].addr1


		if src in src_to_dest:
			src_to_dest.get(src).append(dest)
		else:
			src_to_dest[src] = [dest]

dataFile.write(str(src_to_dest))

printDict(src_to_dest)


