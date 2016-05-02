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

def ping_one(dst,id_no,seq_no,ttl_no):
	send_time = time.time()
	time_in_bytes = struct.pack('>d',send_time)
	ping_one_reply = sr1(IP(dst=dst, ttl=ttl_no)/ICMP(id=id_no,seq=seq_no)/time_in_bytes, timeout = 1, verbose=False)
	try:
		if ping_one_reply.getlayer(ICMP).type == 0 and ping_one_reply.getlayer(ICMP).code == 0 and ping_one_reply.getlayer(ICMP).id == id_no:
			reply_source_ip = ping_one_reply.getlayer(IP).src
			reply_seq = ping_one_reply.getlayer(ICMP).seq
			reply_ttl = ping_one_reply.getlayer(IP).ttl
			reply_data_length = len(ping_one_reply.getlayer(Raw).load) + len(ping_one_reply.getlayer(Padding).load) + 8
			reply_data = ping_one_reply.getlayer(Raw).load
			receive_time = time.time()
			echo_request_sendtime = struct.unpack('>d',reply_data)
			time_to_pass_ms = (receive_time-echo_request_sendtime[0]) * 1000
			return reply_data_length, reply_source_ip, reply_seq, reply_ttl, time_to_pass_ms
	except Exception as e:
		if re.match('.*NoneType.*',str(e)):
			return None

def qyt_ping(dst):
	id_no = random.randint(1,65535)
	for i in range(1,6):
		ping_result = ping_one(dst,id_no,i,64)
		if ping_result:
			print('%d bytes from %s: icmp_seq=%d ttl=%d time=%4.2f ms' % (ping_result[0], ping_result[1], ping_result[2], ping_result[3], ping_result[4]))
		else:
			print('.',end='',flush=True)
		time.sleep(1)

if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')
	destination = sys.argv[1]
	qyt_ping(destination)