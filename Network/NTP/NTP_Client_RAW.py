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

import socket
import struct
import sys
import time
import optparse

TIME_1970 = 2208988800

def ntp_client(NTP_SERVER):
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#socket.AF_INET为IP，socket.SOCK_DGRAM为UDP
	data = b'\x1b' + 47 * b'\0' #\x1b(00 011(版本3) 011(客户模式)) + 47个\0凑齐48个字节的头部
	client.sendto(data, (NTP_SERVER, 123))#数据，IP地址和端口号
	data, address = client.recvfrom(1024)#接收缓存为1024
	if data:
		print('Response received from:', address)#如果收到数据，打印地址信息
	s = struct.unpack('!12I', data)#48个字节，12个四字节
	#print (s)
	t = struct.unpack('!12I', data)[10]#倒数第二个为时间
	#print(t)
	t -= TIME_1970#Linux 自己的系統時間，由 1970/01/01 開始記錄的時間參數
	#print(t)
	print('\tTime=%s' %time.ctime(t))

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 NTP_Client_RAW.py --server NTP服务器')
	parser.add_option('--server', dest = 'server', type = 'string', help = 'NTP服务器')
	(options, args) = parser.parse_args()
	server = options.server
	if server == None:
		print(parser.usage)
	else:
		ntp_client(server)
		#'0.uk.pool.ntp.org'