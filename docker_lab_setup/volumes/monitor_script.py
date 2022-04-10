from scapy.all import *
import os
import sqlite3
from sqlite3 import Error



def monitorConnectons(p):
    print('src -- '+p[IP].src,' dst -- '+p[IP].dst)

    
    



sniff(filter="tcp port 8000",prn=monitorConnectons)