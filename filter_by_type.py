a = int(input("vlozte cislo ramce(1-ridici, 0-management, 2-datove)"))
pk = rdpcap('test.pcap')
filtered = dict()
for pkt in pk:
        if Dot11 in pkt:
            if pkt[Dot11].type == a:
                if pkt[Dot11].addr3 in filtered:
                     filtered[pkt[Dot11].addr3]=(pkt[Dot11].addr1, pkt[Dot11].ID)
                else:
                     filtered[pkt[Dot11].addr3] = []
                     filtered[pkt[Dot11].addr3] = (pkt[Dot11].addr1, pkt[Dot11].ID)

print(filtered)
#quit()
