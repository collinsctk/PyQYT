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
#from GET_IP import get_ip_address #获取本机IP地址
from PyQYT.Network.Tools.GET_IP import get_ip_address #获取本机IP地址
from PyQYT.Network.Tools.GET_MAC import get_mac_address #获取本机MAC地址
import optparse
#test github
#获取指定IP的MAC地址，要指定发送ARP请求的接口

def get_arp(ip_address, ifname):
	#localip = get_ip_address(ifname)
	#获取本机IP地址
	localip = get_ip_address(ifname)
	#获取本机MAC地址
	localmac = get_mac_address(ifname)
	#发送ARP请求并等待响应
	result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=ip_address), iface = ifname, verbose = False)
	#把响应的数据包对，产生为清单
	result_list = result_raw[0].res
	#[0]第一组响应数据包
	#[1]接受到的包，[0]为发送的数据包
	#[1]ARP头部字段中的['hwsrc']字段，作为返回值返回
	return result_list[0][1][1].fields['hwsrc']

if __name__ == "__main__":
	parser = optparse.OptionParser('用法：\n python3 ARP_def.py --ip 目标IP --ifname 本地接口名')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = '指定要查询的目标IP')
	parser.add_option('--ifname', dest = 'ifname', type = 'string', help = '指定发送ARP请求的本地接口名')
	(options, args) = parser.parse_args()
	ip = options.ip
	ifname = options.ifname
	if ip == None or ifname == None:
		print(parser.usage)
	else:
		print('IP地址: ' + ip + ' MAC地址: ' + get_arp(ip, ifname))
