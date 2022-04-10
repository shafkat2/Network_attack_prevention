



def routing(p):
	newpkt = IP(bytes(p[IP]))
	del(newpkt.chksum)
	del(newpkt[TCP].payload)
	del(newpkt[TCP].chksum)
	newpkt[IP].dst = newpkt[IP].src
	send(newpkt)


sniff(filter="Tcp port 8000",prn=routing)