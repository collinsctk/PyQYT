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

import struct
import socket
import time
import os
import optparse
from PyQYT.Network.Tools.Checksum import do_checksum

def ping_one_raw(dst,seq_no):
	send_time = time.time() #计算时间1462346467.457762
	time_in_bytes = struct.pack('d',send_time)
	#把时间转为2进制，d为8个字节浮点，不要转换为网络字节序，计算校验和的函数是按照主机字节序计算的！
	my_checksum = 0
	header = struct.pack('bbHHH', 8, 0, my_checksum, (os.getpid() & 0xffff), int(seq_no))#在校验和为0的情况下构造头部
	#由于计算校验和的函数是按照主机字节序计算的！所以保持默认的主机字节序
	payload = struct.pack('18s', b'welcome to qytang!')#构造等待发送的二进制数据！
	#由于计算校验和的函数是按照主机字节序计算的！所以保持默认的主机字节序
	my_checksum = do_checksum(header + time_in_bytes + payload)#把头部，时间，数据放在一起计算校验和！
	#由于计算校验和的函数是按照主机字节序计算的！所以保持默认的主机字节序
	icmp_id = (os.getpid() & 0xffff)#获得进程ID，作为ICMP ECHO的ID
	header = struct.pack('bbHHH', 8, 0, int(my_checksum), icmp_id, int(seq_no))#添加上计算的校验和，构造成为最终的ICMP头部
	packet = header + time_in_bytes + payload#把头部，时间，负载连接在一起成为待发送的数据包
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)#创建socket实例，1表示icmp协议
	sock.sendto(packet, (dst, 1))#发送ICMP数据包到目的地，注意此时socket会自动把主机字节序自动转换为网络字节序
	recv_packet, addr = sock.recvfrom(1024)#接收数据包
	receive_time = time.time()#计算接收到数据包的时间
	header = struct.unpack('bbHHH',recv_packet[20:28])#解包ICMP头部！
	if header[3] == icmp_id and header[4] == seq_no:#如果ICMP ID和序列号都匹配！
		echo_request_sendtime = struct.unpack('d',recv_packet[28:36])#解包时间！
		time_to_pass_ms = (receive_time - echo_request_sendtime[0]) * 1000#计算时间差，单位为毫秒
		print('Echo Reply Received time=%4.2f ms' % time_to_pass_ms)#打印结果
	else:
		print('.', flush=True)#其他情况打印'.'

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 PING_RAW.py --ip 目标IP')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = '指定要查询的目标IP')
	(options, args) = parser.parse_args()
	ip = options.ip
	if ip == None:
		print(parser.usage)
	else:
		ping_one_raw(ip, 10)
