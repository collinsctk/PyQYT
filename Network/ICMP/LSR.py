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
import time
import struct
import random
import sys
import re


def try_lsr(dst,lsr_hop,option=1):
	ip_sec = dst.split('.')
	sec_1 = struct.pack('>B', int(ip_sec[0]))
	sec_2 = struct.pack('>B', int(ip_sec[1]))
	sec_3 = struct.pack('>B', int(ip_sec[2]))
	sec_4 = struct.pack('>B', int(ip_sec[3]))

	ip_options = b'\x83\x07\x04' + sec_1 + sec_2 + sec_3 + sec_4 + b'\x00'

	if option == 1:
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/ICMP(type=8,code=0)
		result = sr1(pkt,timeout = 1, verbose=True)

#		try:
#			if result.getlayer(ICMP).type == 0 and result.getlayer(ICMP).code == 0:
#				print('源站路由Ping测试通过！')
#		except Exception as e:
#			if re.match('.*NoneType.*',str(e)):
#				print('源站路由Ping测试,目标不可达！')

	elif option == 2:
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/TCP(dport=23)
		result = sr1(pkt,timeout = 1, verbose=True)

#		try:
#			if result.getlayer(TCP).flags == 18:
#				print('源站路由TCP SYN测试通过！')
#		except Exception as e:
#			if re.match('.*NoneType.*',str(e)):
#				print('源站路由TCP SYN测试,目标不可达！')
#
#	else:
#		print('选项设置错误,"1"为PING测试,"2"为TCP SYN测试')

if __name__ == '__main__':
	destination = sys.argv[1]
	lsr_route = sys.argv[2]
	option = int(sys.argv[3])
	try_lsr(destination, lsr_route, option)