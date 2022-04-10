from scapy.all import *
import os
import sqlite3
from sqlite3 import Error


communications = {}
def monitorConnectons(p):
	ip_src =  p[IP].src		
	ip_dst =  p[IP].dst
	if p[IP].src != '10.9.0.5':

		if ip_src not in communications:
			communications[ip_src] = {'time':p.time ,'trusted':True,'origin':'outside'}
		elif communications[ip_src]['trusted'] == False and communications[ip_src]['origin'] == 'outside':
			routing(p)
		else:
			if communications[ip_src]['trusted'] ==True and (p.time - communications[ip_src]['time']) < 1:
				communications[ip_src]['trusted'] = False
				conn = create_connection('global.db')
				enter_info(conn,ip_src,"singelip_multiport")
				os.system("iptables -A INPUT -s "+ip_src+" -j DROP")	
				print('ip saved in database and forwarded')

			communications[ip_src]['time'] = p.time
		
def routing(p):
	newpkt = IP(bytes(p[IP]))
	del(newpkt.chksum)
	del(newpkt[TCP].payload)
	del(newpkt[TCP].chksum)
	newpkt[IP].dst = '10.9.0.7'
	send(newpkt)


def create_connection(db_path):
	conn = None
	try:
		conn = sqlite3.connect(db_path)
	except Error as e:
		print(e)

	return conn


def enter_info(conn,ip,source):

	cur = conn.cursor()

	cur.execute("INSERT into _ddos(IP,type) VALUES(?,?)",(ip,source))
	conn.commit()



sniff(filter="tcp port 8000",prn=monitorConnectons)