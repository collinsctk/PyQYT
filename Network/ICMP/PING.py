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

def ping_one(dst,id_no,seq_no,ttl_no):
	send_time = time.time() #计算时间1462346467.457762
	time_in_bytes = struct.pack('>d',send_time)#把时间转为2进制，'>'为网络字节序，d为8个字节浮点
	#d unpack后结果(1462346530.915078,)， f unpack后结果(1462346496.0,)，f的精度明显不够
	ping_one_reply = sr1(IP(dst=dst, ttl=ttl_no)/ICMP(id=id_no,seq=seq_no)/time_in_bytes, timeout = 1, verbose=False)
	#产生一个ICMP echo request数据包，scapy默认类型为echo request，数据部分为2进制编码后的时间
	try:
		if ping_one_reply.getlayer(ICMP).type == 0 and ping_one_reply.getlayer(ICMP).code == 0 and ping_one_reply.getlayer(ICMP).id == id_no:
		#收到的数据包，要为echo reply（type为0，code为0），并且id位还要匹配。
			reply_source_ip = ping_one_reply.getlayer(IP).src
			#提取echo reply的源IP地址
			reply_seq = ping_one_reply.getlayer(ICMP).seq
			#提取echo reply的序列号
			reply_ttl = ping_one_reply.getlayer(IP).ttl
			#提取echo reply的TTL
			reply_data_length = len(ping_one_reply.getlayer(Raw).load) + len(ping_one_reply.getlayer(Padding).load) + 8
			#数据长度等于 数据长度（Raw） + 垫片长度（Padding） + 8字节（ICMP头部长度）
			reply_data = ping_one_reply.getlayer(Raw).load
			#提取数据（Raw）
			receive_time = time.time()
			#计算接收的时间
			echo_request_sendtime = struct.unpack('>d',reply_data)
			#把二进制的数据转换为发送时间
			time_to_pass_ms = (receive_time-echo_request_sendtime[0]) * 1000
			#（接收时间 - 发送时间） * 1000为毫秒数为消耗时间的毫秒数
			return reply_data_length, reply_source_ip, reply_seq, reply_ttl, time_to_pass_ms
			#返回echo reply中的数据总长度，源IP，序列号，TTL，和消耗的时间
	except Exception as e:
		if re.match('.*NoneType.*',str(e)):
			#如果没有回应，就返回None
			return None

def qyt_ping(dst):
	id_no = random.randint(1,65535)#随机产生ID号
	for i in range(1,6): #ping 五个包
		ping_result = ping_one(dst,id_no,i,64)
		if ping_result:#把返回的值打印出来
			print('%d bytes from %s: icmp_seq=%d ttl=%d time=%4.2f ms' % (ping_result[0], ping_result[1], ping_result[2], ping_result[3], ping_result[4]))
		else:
			print('.',end='',flush=True)#如果没有回应就打印'.'，注意flush选项，默认会缓存并不直接打印
		time.sleep(1)#间隔一秒发送数据包

if __name__ == '__main__':
	conf.route.add(net='202.100.0.0/16',gw='202.100.1.3')#为scapy添加路由
	parser = optparse.OptionParser('用法：\n python3 PING.py --ip 目标IP')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = '目标IP')
	(options, args) = parser.parse_args()
	ip = options.ip
	if ip == None:
		print(parser.usage)
	else:
		qyt_ping(ip)