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

def Tracert_one(dst,dport,ttl_no):
	send_time = time.time()
	Tracert_one_reply = sr1(IP(dst=dst, ttl=ttl_no)/UDP(dport=dport)/b'qytang traceroute!!!', timeout = 1, verbose=False)
	try:
		if Tracert_one_reply.getlayer(ICMP).type == 11 and Tracert_one_reply.getlayer(ICMP).code == 0:
			hop_ip = Tracert_one_reply.getlayer(IP).src
			received_time = time.time()
			time_to_passed = (received_time - send_time) * 1000
			return 1, hop_ip, time_to_passed
		elif Tracert_one_reply.getlayer(ICMP).type == 3 and Tracert_one_reply.getlayer(ICMP).code == 3:
			hop_ip = Tracert_one_reply.getlayer(IP).src
			received_time = time.time()
			time_to_passed = (received_time - send_time) * 1000
			return 2, hop_ip, time_to_passed
	except Exception as e:
		if re.match('.*NoneType.*',str(e)):
			return None

def QYT_Tracert(dst,hops):
	dport = 33434
	hop = 0
	while hop < hops:
		dport = dport + hop
		hop += 1
		Result = Tracert_one(dst,dport,hop)
		if Result == None:
			print(str(hop) + ' *',flush=True)
		elif Result[0] == 1:
			time_to_pass_result = '%4.2f' % Result[2]
			print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
		elif Result[0] == 2:
			time_to_pass_result = '%4.2f' % Result[2]
			print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
			break
		time.sleep(1)

if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')
	destination = sys.argv[1]
	hops = int(sys.argv[2])
	QYT_Tracert(destination, hops)
