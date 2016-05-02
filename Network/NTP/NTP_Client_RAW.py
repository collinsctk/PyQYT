#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import socket
import struct
import sys
import time

TIME_1970 = 2208988800

def ntp_client(NTP_SERVER):
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = '\x1b' + 47 * '\0'
	client.sendto(data.encode(), (NTP_SERVER, 123))
	data, address = client.recvfrom(1024)
	if data:
		print('Response received from:', address)
	s = struct.unpack('!12I', data)
	print (s)
	t = struct.unpack('!12I', data)[10]
	print(t)
	t -= TIME_1970
	#print(t)
	print('\tTime=%s' %time.ctime(t))

if __name__ == '__main__':
	ntp_client('0.uk.pool.ntp.org')






