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
import re

def pcap_parser(filename, keyword):
	pkts=rdpcap(filename)
	return_pkts_list = []
	for pkt in pkts.res:
		try:
			pkt_load = pkt.getlayer('Raw').fields['load'].decode().strip()
			re_keyword = '.*'+keyword+'.*'
			if re.match(re_keyword, pkt_load) and pkt.getlayer('TCP').fields['sport'] == 23:
				return_pkts_list.append(pkt)
		except:
			pass
	return return_pkts_list
if __name__ == "__main__":	
	pkts = pcap_parser("login_invalid.pcap", 'invalid')
	for pkt in pkts:
		print(pkt.getlayer('Raw').fields)
		print(pkt.getlayer('TCP').fields)
		print(pkt.getlayer('IP').fields)
