## File format:
# SR:CM:AC:AD:DR:ES Optional comment, but the space after the MAC is required (because we are using str.split() in a wrong way, FIXME.
# <TAB> DE:ST:MA:CA:DD:RE (Time.usec;length)
import sys

def frameToSrcDest(frame):
    if frame[Dot11].type != 2 or frame[Dot11].subtype != 8:
        return (None, None)         # We need to return a tuple, else we break asignments in the program.
    if frame[Dot11].FCfield & 0x1:    #From device to router
        src = frame[Dot11].addr1
        dest = frame[Dot11].addr3
    elif frame[Dot11].FCfield & 0x2:    #From router to device
        src = frame[Dot11].addr3
        dest = frame[Dot11].addr1
    else:
        src = dest = None
    return (src, dest)



class FrameData:
    def fromFrame(self, frame):
        self.src, self.dest = frameToSrcDest(frame)
        self.time = frame.time
        self.length = len(frame)
    def fromData(self, src, dest, time, length):
        self.src = src
        self.dest = dest
        self.time = time
        self.length = length

class Log:
    items = dict()      # Indexed by source, contains lists of FrameData's
    comments = dict()   # Indexed by source, contains strings of comments
    def insertFrame(self, frame):
        fd = FrameData()
        fd.fromFrame(frame)
        self.insert(fd)
    def insert(self, framedata):
        # TODO: Check, that we do not already have the frame logged
        # - Assume that one device could not send multiple frames to the same other device in the same milisecond
        if framedata.src not in self.items:
            self.items[framedata.src] = []
        self.items[framedata.src].append(framedata)
    def print(self):
        self.writeToFileHandle(sys.stdout)
    def writeToFile(self, filename):
        fh = open(filename, "w")
        self.writeToFileHandle(fh)
        close(fh)
    def writeToFileHandle(self, fh):
        for src in items:
            # Do not print frames which do not have a source (e.g. acknowledgements)
            if src == None:
                continue
            if src in comments:
                fh.write("{} {}\n".format(src, comments[src]))
            else:
                fh.write("{} \n".format(src))
            for fd in items[src]:
                fh.write("\t{} ({}, {})\n".format(fd.dest, fd.time, fd.length))
            fh.write('\n')
    def addFromFile(self, filename):
        fh = open(filename, "r")
        self.addFromFileHandle(fh)
        close(fh)
    def addFromFileHandle(self, fh):
        currentSrc = None
        while True: # FIXME: detect EOF in a sane way
            line = fh.readline()
            if line.startswith('\t'):
                # Add a record for the current source
                dest, rest = line.split(" ", 1)
                rest = rest.strip(['(', ')'])
                time, length = rest.split(';', 1)
                fd = FrameData()
                fd.fromData(currentSrc, dest, float(time), int(length))
                self.insert(fd)
            else:
                # Only change the current Source and save optional comment
                currentSrc, comment = line.split(' ', 1)
                if comment != '':
                    self.comments[currentSrc] = comment
    def addFromPcap(self, filename):
        sniff(offline=filename, store=False, prn=self.insertFrame)

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
            src, dest = frameToSrcDest(pkt)
            if src in src_to_dest:
                src_to_dest.get(src).append(dest)
            else:
                src_to_dest[src] = [dest]
    return src_to_dest

# Main
dataFile = open("./AnalyticData/data.txt", "w")
src_to_dest = readcap("test.pcap")
print("Let us analyze your PCAP data")
print("Tell us what you want to do:")
while True:
    print(
        "[1] Load new PCAP file\n" +
        "[2] Show traffic log\n" +
        "[3] Match MAC address with a name\n" +
        "[4] End"
    )
    usrChoice = input()
    if usrChoice == '1':
        print("What's the name of the file?")
        readcap(input())
        print("File loaded")
    if usrChoice == '2':
        printDict(count(src_to_dest))
    if usrChoice == '3':
        pass
        ##### YET TO BE DONE #####
    if usrChoice == '4':
        exit()
    print("Task finished.\n")
    print("Do you want to do something else?")
