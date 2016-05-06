#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

def tcp_connection(ip, port):
	#设置目的端口号
	dstport = port
	#随机产生源端口
	sportid = random.randint(1024, 65535)
	#随机产生目的端口
	seqid = random.randint(1, 65535*65535)

	#产生SYN包（FLAG = 2 为SYN）并等待回应####源端口调用随机端口，序列号调用随机序列号
	result_raw_synack = sr(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=2,seq=seqid), verbose = False)

	#响应的数据包产生数组([0]为响应，[1]为未响应)
	result_synack_list = result_raw_synack[0].res

	#第一层[0]为第一组数据包
	#第二层[0]表示发送的包，[1]表示收到的包
	#第三层[0]为IP信息，[1]为TCP信息，[2]为TCP数据
	tcpfields_synack = result_synack_list[0][1][1].fields

	#由于SYN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
	sc_sn = tcpfields_synack['seq'] + 1
	cs_sn = tcpfields_synack['ack']

	#发送ACK(flag = 16),完成三次握手！
	send(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)

	#发送数据（b"Welcome to qytang"），flag为24（ACK = 16，PUSH = 8)
	#注意‘multi=1’，服务器会先给一个ACK确认，然后发送回显数据。
	#如果客户没有及时确认，还会有多次重传！
	result_raw_msg = sr(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=24,seq=cs_sn,ack=sc_sn)/b"Welcome to qytang", verbose = False, multi=1, timeout=1)

	#响应的数据包产生数组([0]为响应，[1]为未响应)
	result_msg_list = result_raw_msg[0].res

	#提取服务器响应包的IP信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
	msgback_ip_fields = result_msg_list[1][1][0].fields
	#提取服务器响应包的TCP信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
	msgback_tcp_fields = result_msg_list[1][1][1].fields
	#提取服务器响应包的TCP数据信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
	msgback_data_fields = result_msg_list[1][1][2].fields

	#如果回显数据中有‘Echo’字段就打印回显内容
	if re.search(b'Echo', msgback_data_fields['load']):
		print(msgback_data_fields['load'])

	#计算数据长度，ip总长度 - ip头部长度（['ihl']*4） - tcp头部长度（['dataofs']*4）
	data_len = msgback_ip_fields['len'] - msgback_ip_fields['ihl']*4 - msgback_tcp_fields['dataofs']*4

	#客户到服务器端的序列号为，服务器回显中的‘seq’加上传输的数据长度！
	sc_sn = msgback_tcp_fields['seq'] + data_len
	cs_sn = msgback_tcp_fields['ack']

	#发送ACK对服务器的回显进行确认，flag = 16（ACK）
	send(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)

	#客户端主动发送FIN（1） + ACK（16），进行连接终结。
	result_raw_fin = sr1(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=17,seq=cs_sn,ack=sc_sn), verbose = False)

	#由于FIN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
	sc_sn = result_raw_fin[1].fields['seq'] + 1
	cs_sn = result_raw_fin[1].fields['ack']

	#发送最后一个ACK（16），结束整个TCP连接！！！
	send(IP(dst=ip)/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)

if __name__ == '__main__':
	tcp_connection('202.100.1.138', 6666)