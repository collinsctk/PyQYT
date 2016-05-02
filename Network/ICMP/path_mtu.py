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

def ping_df(dst,mtu):
	pyload = b'v'*(int(mtu) - 28)

	ping_one_reply = sr1(IP(dst=dst,flags='DF')/ICMP()/pyload, timeout = 1, verbose=False)
	try:
		if ping_one_reply.getlayer(ICMP).type == 3 and ping_one_reply.getlayer(ICMP).code == 4:
			return 1, mtu
		elif ping_one_reply.getlayer(ICMP).type == 0 and ping_one_reply.getlayer(ICMP).code == 0:
			return 2, mtu
	except Exception as e:
		if re.match('.*NoneType.*',str(e)):
			return None
def discover_path_mtu(dst):
	mtu = 1500
	while True:
		Result = ping_df(dst,mtu)
		if Result == None:
			print('目标: ' + dst + '不可达！')
			break
		elif Result[0] == 2:
			print('目标: ' + dst + '的Path MTU为: ' + str(Result[1]))
			break
		elif Result[0] == 1:
			mtu = mtu - 10
			print('MTU: ' + str(mtu) + '测试不通过')
		time.sleep(1)






if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')
	destination = sys.argv[1]
	discover_path_mtu(destination)