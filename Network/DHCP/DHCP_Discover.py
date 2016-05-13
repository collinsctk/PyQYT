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
from PyQYT.Network.Tools.GET_MAC import GET_MAC
from PyQYT.Network.Tools.Change_MAC_To_Bytes import Change_MAC_To_Bytes
import time
import optparse

def DHCP_Discover_Sendonly(ifname, MAC, wait_time = 1):
	if wait_time != 0:
		time.sleep(wait_time)
		Bytes_MAC = Change_MAC_To_Bytes(MAC)#把MAC地址转换为二进制格式
		#chaddr一共16个字节，MAC地址只有6个字节，所以需要b'\x00'*10填充到16个字节
		#param_req_list为请求的参数，没有这个部分服务器只会回送IP地址，什么参数都不给
		discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=MAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=Bytes_MAC + b'\x00'*10) / DHCP(options=[('message-type','discover'), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])
		sendp(discover, iface = ifname, verbose=False)
	else:
		Bytes_MAC = Change_MAC_To_Bytes(MAC)
		discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=MAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=Bytes_MAC + b'\x00'*10) / DHCP(options=[('message-type','discover'), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])
		sendp(discover, iface = ifname, verbose=False)	

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 DHCP_Discover.py --ifname 本地接口名')
	parser.add_option('--ifname', dest = 'ifname', type = 'string', help = '指定发送DHCP请求的本地接口名')
	(options, args) = parser.parse_args()
	ifname = options.ifname
	if ifname == None:
		print(parser.usage)
	else:
		Local_MAC = GET_MAC(ifname)
		DHCP_Discover_Sendonly(ifname, Local_MAC)