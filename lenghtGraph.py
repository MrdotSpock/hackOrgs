import scapy
import numpy as np
import matplotlib.pyplot as plt

pk = rdpcap('test.pcap')

sourceAdress = '00:19:99:fa:64:e4'
uploadList = []
downloadList = []

for pkt in pk:
    if Dot11 in pkt and pkt[Dot11].addr3 == sourceAdress:
        if pkt[Dot11].type == 2 and pkt[Dot11].subtype == 8:
            if pkt[Dot11].FCfield & "to-DS":
                downloadList.append((len(pkt), pkt.time))
            elif pkt[Dot11].FCfield & "from-DS":
                uploadList.append((len(pkt), pkt.time))

plt.plot(list(map(lambda x: x[1], uploadList)),
    list(map(lambda x: x[0], uploadList)),
    label='upload')

plt.plot(list(map(lambda x: x[1], downloadList)),
    list(map(lambda x: x[0], downloadList)),
    label='download')    

plt.title("packets flow for device: " + sourceAdress)
plt.xlabel("time")
plt.ylabel("packet lenght")

plt.legend()
plt.show()