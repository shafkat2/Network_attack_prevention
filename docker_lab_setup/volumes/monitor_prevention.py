from scapy.all import *
import os
import sqlite3
from sqlite3 import Error


communications = {}
def monitorConnectons(p):
	if p[ICMP].type == 5:
		ip_src =  p[IP].src		
		ip_dst =  p[IP].dst
		print('gw '+p[ICMP].gw,'ip src ' + ip_src)
		if (ip_src,ip_dst) not in communications:
			communications[(ip_src,ip_dst)] = {'time':p.time ,'trusted':True}
		else:
		  if communications[(ip_src,ip_dst)]['trusted'] ==True and (p.time - communications[(ip_src,ip_dst)]['time']) < 25:
			  communications[(ip_src,ip_dst)]['trusted'] = False
			  conn = create_connection('global.db')
			  os.system("ip route flush table main")	
			  enter_info(conn,p[ICMP].gw,ip_src)
			  print('ip saved')

		  communications[(ip_src,ip_dst)]['time'] = p.time
		
		

def create_connection(db_path):
	conn = None
	try:
		conn = sqlite3.connect(db_path)
	except Error as e:
		print(e)

	return conn


def enter_info(conn,ip,source):

	cur = conn.cursor()

	cur.execute("INSERT into _icmp(IP,source) VALUES(?,?)",(ip,source))
	conn.commit()



sniff(filter="icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply",prn=monitorConnectons)