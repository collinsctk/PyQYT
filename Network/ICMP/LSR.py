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
	#我们需要把正真目的地址写在IP选项，把宽松源站路由地址写成IP的目的地址
	ip_sec = dst.split('.') #首先把IP地址通过'.'分为四段
	sec_1 = struct.pack('>B', int(ip_sec[0]))#每一段写成一个字节的二进制数
	sec_2 = struct.pack('>B', int(ip_sec[1]))
	sec_3 = struct.pack('>B', int(ip_sec[2]))
	sec_4 = struct.pack('>B', int(ip_sec[3]))

	ip_options = b'\x83\x07\x04' + sec_1 + sec_2 + sec_3 + sec_4 + b'\x00'

	if option == 1:
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/ICMP(type=8,code=0)
		result = sr1(pkt,timeout = 1, verbose=True)

	elif option == 2:
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/TCP(chksum=0xe977,sport=1024,dport=23)
		result = sr1(pkt,timeout = 1, verbose=True)

if __name__ == '__main__':
	destination = sys.argv[1]
	lsr_route = sys.argv[2]
	option = int(sys.argv[3])
	try_lsr(destination, lsr_route, option)