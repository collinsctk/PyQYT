#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import time
import struct
import random
import sys
import re
import optparse

def try_lsr(dst,lsr_hop,option=1):
	#我们需要把正真目的地址写在IP选项，把宽松源站路由地址写成IP的目的地址
	ip_sec = dst.split('.') #首先把IP地址通过'.'分为四段
	sec_1 = struct.pack('>B', int(ip_sec[0]))#每一段写成一个字节的二进制数
	sec_2 = struct.pack('>B', int(ip_sec[1]))
	sec_3 = struct.pack('>B', int(ip_sec[2]))
	sec_4 = struct.pack('>B', int(ip_sec[3]))

	ip_options = b'\x83\x07\x04' + sec_1 + sec_2 + sec_3 + sec_4 + b'\x00'
	#\x83表示宽松源站路由，\x07表示长度，\x04表示指针，紧跟着四个字节的IP地址（正真的目的地址），然后补齐8字节边界

	if option == 1:#选项1表示ICMP源站路由
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/ICMP(type=8,code=0)
		#目的地址为源站路由的地址，正真的目的地址放在IP选项内
		result = sr1(pkt,timeout = 1, verbose=True)

	elif option == 2:#选项2表示TCP源站路由
		pkt = IP(dst=lsr_hop, options=IPOption(ip_options))/TCP(chksum=0xe977,sport=1024,dport=23)
		#目的地址为源站路由的地址，正真的目的地址放在IP选项内
		#由于TCP校验和计算包括IP地址，但是IP地址又被修改了，所以TCP校验和需要修改
		result = sr1(pkt,timeout = 1, verbose=True)

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 LSR.py --dest 目标IP --lsr_route lsr_route --option 选项')
	parser.add_option('--dest', dest = 'dest', type = 'string', help = '目标IP')
	parser.add_option('--lsr_route', dest = 'lsr_route', type = 'string', help = 'lsr_route')
	parser.add_option('--option', dest = 'option', type = 'string', help = '选项1表示ICMP源站路由，选项2表示TCP源站路由')
	(options, args) = parser.parse_args()
	dest = options.dest
	lsr_route = options.lsr_route
	option = options.option

	if dest == None or lsr_route == None or option == None:
		print(parser.usage)
	else:
		try_lsr(dest, lsr_route, option)
