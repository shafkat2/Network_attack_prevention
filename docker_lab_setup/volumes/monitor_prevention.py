from scapy.all import *
import os



communications = {}
def monitorConnectons(p):
	#print(p)
	if p[ICMP].type == 5:
		ip_src =  p[IP].src		
		ip_dst =  p[IP].dst
		print('gw'+p[ICMP].gw)
		if (ip_src,ip_dst) not in communications:
			communications[(ip_src,ip_dst)] = {'time':p.time ,'trusted':True}
		else:
		  if p.time -communications[(ip_src,ip_dst)]['trusted'] =='False' or (p.time -communications[(ip_src,ip_dst)]['time']) < 25:
			  communications[(ip_src,ip_dst)]['trusted'] = False
			  print(ip_src)
		
		#os.system("sudo iptables -I INPUT -s "+ip_src+" -j DROP.")	
def changeRoutingConnections(p):
	"code the routing configuration"
		
sniff(filter="icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply",prn=monitorConnectons)