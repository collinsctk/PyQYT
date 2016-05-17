#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import socket
import fcntl
import struct
import optparse
  
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (ifname[:15]).encode())
    )[20:24])

if __name__ == "__main__":
	parser = optparse.OptionParser('用法：\n python3 GET_IP.py --ifname 接口名')
	parser.add_option('--ifname', dest = 'ifname', type = 'string', help = '要查询的接口的名字')
	(options, args) = parser.parse_args()
	ifname = options.ifname
	if ifname == None:
		print(parser.usage)
	else:
		print(get_ip_address(ifname))
