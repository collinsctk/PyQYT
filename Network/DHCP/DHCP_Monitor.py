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
from PyQYT.Network.Tools.Change_Chaddr_To_MAC import Change_Chaddr_To_MAC

def DHCP_Monitor(pkt):
	try:
		if pkt.getlayer(DHCP).fields['options'][0][1]== 1:#发现并且打印DHCP Discover
			print('发现DHCP Discover包，MAC地址为:',end='')
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			MAC_ADDR = Change_Chaddr_To_MAC(MAC_Bytes)
			print(MAC_ADDR)
			print('Request包中发现如下Options:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))			
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 2:#发现并且打印DHCP OFFER
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			MAC_ADDR = Change_Chaddr_To_MAC(MAC_Bytes)
			print('发现DHCP OFFER包，请求者得到的IP为:' + pkt.getlayer(BOOTP).fields['yiaddr'])
			print('OFFER包中发现如下Options:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 3:#发现并且打印DHCP Request
			print('发现DHCP Request包，请求的IP为:' + pkt.getlayer(BOOTP).fields['yiaddr'])
			print('Request包中发现如下Options:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 5:#发现并且打印DHCP ACK
			print('发现DHCP ACK包，确认的IP为:' + pkt.getlayer(BOOTP).fields['yiaddr'])
			print('ACK包中发现如下Options:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
	except Exception as e:   
		print(e)
		pass

def DHCP_Sinffer(ifname):
	sniff(prn=DHCP_Monitor, filter="port 68 and port 67", store=0, iface=ifname)

if __name__ == '__main__':
	DHCP_Sinffer('eno33554944')
