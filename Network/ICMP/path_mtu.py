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

def ping_df(dst,mtu):
	pyload = b'v'*(int(mtu) - 28)

	ping_one_reply = sr1(IP(dst=dst,flags='DF')/ICMP()/pyload, timeout = 1, verbose=False)
	try:
		#type 3 code 4：目标不可达，因为数据包太大需要分段，但是DF被设置
		if ping_one_reply.getlayer(ICMP).type == 3 and ping_one_reply.getlayer(ICMP).code == 4:
			return 1, mtu
		#type 0 code 0：收到目标的回复
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
			print('目标可达，增加MTU！')
			mtu += 8
		elif Result[0] == 1:
			mtu = mtu - 8
			print('目标不可达，减小MTU！')
		time.sleep(1)
	print('MTU: ' + str(mtu-8))

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 path_mtu.py --ip 目标IP')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = '指定要查询的目标IP')
	(options, args) = parser.parse_args()
	ip = options.ip
	if ip == None:
		print(parser.usage)
	else:
		discover_path_mtu(ip)