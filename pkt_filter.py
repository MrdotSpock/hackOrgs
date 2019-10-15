# Functions
def printDict(dictionary):
    for src in dictionary.keys():
        print(src)
        for dest in dictionary[src]:
            print("\t" + str(dest))
        print()

def count(dictionary):
    dict_of_names = dict()
    final_dict = dict()
    for key in dictionary:
        for addr in dictionary[key]:
            if addr in dict_of_names:
                dict_of_names[addr] += 1
            else:
                dict_of_names[addr] = 1
        for i in dict_of_names:
            if key in final_dict:
                x = (i, dict_of_names[i])
                final_dict[key].append(x)
            else:
                final_dict[key] = []
                x = (i, dict_of_names[i])
                final_dict[key].append(x)
        dict_of_names.clear()
    return final_dict

def readcap(filename):
    pkts = rdpcap("test.pcap")
    src_to_dest = dict()

    for pkt in pkts:
    if pkt[Dot11].type == 2 and pkt[Dot11].subtype == 8:
        src = ""
        dest = ""

        if pkt[Dot11].FCfield & 0x1:    #From device to router
            src = pkt[Dot11].addr1
            dest = pkt[Dot11].addr3
        elif pkt[Dot11].FCfield & 0x2:    #From router to device
            src = pkt[Dot11].addr3
            dest = pkt[Dot11].addr1

        if src in src_to_dest:
            src_to_dest.get(src).append(dest)
        else:
            src_to_dest[src] = [dest]
    pkts.close()
return src_to_dest

# Main
dataFile = open("./AnalyticData/data.txt", "w")
dataFile.write(str(src_to_dest))

printDict(src_to_dest)
print("###########")
printDict(count(src_to_dest))


