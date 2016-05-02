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


def ping_rr(dst,src):
	ip_sec = src.split('.')
	sec_1 = struct.pack('>B', int(ip_sec[0]))
	sec_2 = struct.pack('>B', int(ip_sec[1]))
	sec_3 = struct.pack('>B', int(ip_sec[2]))
	sec_4 = struct.pack('>B', int(ip_sec[3]))

	ip_options = b'\x07\x27\x08' + sec_1 + sec_2 + sec_3 + sec_4 + b'\x00' * 33

	pkt = IP(dst=dst, options=IPOption(ip_options))/ICMP(type=8,code=0)

	result = sr1(pkt,timeout = 1, verbose=False)

	for router in result.getlayer(IP).options[0].fields['routers']:
		print(router)

if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')
	destination = sys.argv[1]
	source = sys.argv[2]
	ping_rr(destination, source)
