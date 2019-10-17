## File format:
# SR:CM:AC:AD:DR:ES (Optional comment, parentheses required (because we are using str.split() in a wrong way, FIXME.))
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
        fh.close()
    def writeToFileHandle(self, fh):
        for src in self.items:
            # Do not print frames which do not have a source (e.g. acknowledgements)
            if src == None:
                continue
            if src in self.comments:
                fh.write("{} ({})\n".format(src, comments[src]))
            else:
                fh.write("{} ()\n".format(src))
            for fd in self.items[src]:
                fh.write("\t{} ({}, {})\n".format(fd.dest, fd.time, fd.length))
            fh.write('\n')
    def addFromFile(self, filename):
        fh = open(filename, "r")
        self.addFromFileHandle(fh)
        fh.close()
    def addFromFileHandle(self, fh):
        currentSrc = None
        while True: # FIXME: detect EOF in a sane way
            line = fh.readline()
            if line == '':
                # EOF
                break
            if line.startswith('\t'):
                # Add a record for the current source
                dest, rest = line.split(" ", 1)
                rest = rest.strip('()\n')
                time, length = rest.split(';', 1)
                fd = FrameData()
                fd.fromData(currentSrc, dest, float(time), int(length))
                self.insert(fd)
            elif line.startswith('\n'):
                continue
            else:
                # Only change the current Source and save optional comment
                currentSrc, comment = line.split(' ', 1)
                if comment != '':
                    self.comments[currentSrc] = comment
    def addFromPcap(self, filename):
        sniff(offline=filename, store=False, prn=self.insertFrame)
    def filterByDest(self, destname):
        result = Log()
        for src in self.items:
            for frdata in self.items[src]:
                if frdata.dest == destname:
                    result.insert(frdata)
        return result


