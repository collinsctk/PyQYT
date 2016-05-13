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

def Tracert_one(dst,dport,ttl_no):#发一个Traceroute包，参数需要目的地址，目的端口，TTL。
	send_time = time.time()#记录发送时间
	Tracert_one_reply = sr1(IP(dst=dst, ttl=ttl_no)/UDP(dport=dport)/b'qytang traceroute!!!', timeout = 1, verbose=False)
	try:
		if Tracert_one_reply.getlayer(ICMP).type == 11 and Tracert_one_reply.getlayer(ICMP).code == 0:
			#如果收到TTL超时
			hop_ip = Tracert_one_reply.getlayer(IP).src
			received_time = time.time()
			time_to_passed = (received_time - send_time) * 1000
			return 1, hop_ip, time_to_passed #返回1表示并未抵达目的地
		elif Tracert_one_reply.getlayer(ICMP).type == 3 and Tracert_one_reply.getlayer(ICMP).code == 3:
			#如果收到端口不可达
			hop_ip = Tracert_one_reply.getlayer(IP).src
			received_time = time.time()
			time_to_passed = (received_time - send_time) * 1000
			return 2, hop_ip, time_to_passed #返回2表示抵达目的地
	except Exception as e:
		if re.match('.*NoneType.*',str(e)):
			return None #测试失败返回None

def QYT_Tracert(dst,hops):
	dport = 33434 #Traceroute的目的端口从33434开始计算
	hop = 0
	while hop < hops:
		dport = dport + hop
		hop += 1
		Result = Tracert_one(dst,dport,hop)
		if Result == None:#如果测试失败就打印‘*’
			print(str(hop) + ' *',flush=True)
		elif Result[0] == 1:#如果未抵达目的，就打印这一跳和消耗的时间
			time_to_pass_result = '%4.2f' % Result[2]
			print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
		elif Result[0] == 2:#如果抵达目的，就打印这一跳和消耗的时间，并且跳出循环！
			time_to_pass_result = '%4.2f' % Result[2]
			print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
			break
		time.sleep(1)

if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')#为Scapy添加路由
	parser = optparse.OptionParser('用法：\n python3 Traceroute.py --ip 目标IP --hops 跳数')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = '指定要查询的目标IP')
	parser.add_option('--hops', dest = 'hops', type = 'string', help = '跳数')
	(options, args) = parser.parse_args()
	ip = options.ip
	hops = options.hops
	if ip == None or hops == None:
		print(parser.usage)
	else:
		QYT_Tracert(ip, int(hops))
