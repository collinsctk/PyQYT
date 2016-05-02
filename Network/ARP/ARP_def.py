#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
#from GET_IP import get_ip_address #获取本机IP地址
from GET_IP_IFCONFIG import get_ip_address_ifconfig #获取本机IP地址
from GET_MAC import get_mac_address #获取本机MAC地址


def get_arp(ip_address, ifname = 'eno33554944'):
	#localip = get_ip_address(ifname)
	#获取本机IP地址
	localip = get_ip_address_ifconfig(ifname)['ip_address']
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
	import sys
	if len(sys.argv) > 1: #./ARP_def 202.100.1.1 xxxxxxx xxxxxxxx
		ipaddress = sys.argv[1] #第一个参数为IP地址
		if len(sys.argv) > 2: #./ARP_def 202.100.1.1 eno33554944 xxxxxxxx
			interface = sys.argv[2] #第二个参数为接口
	if len(sys.argv) > 2: #如果提供接口字段
		print('IP地址: ' + ipaddress + ' MAC地址: ' + get_arp(ipaddress, interface))
	else:#如果未提供接口字段，就使用默认的接口信息
		print('IP地址: ' + ipaddress + ' MAC地址: ' + get_arp(ipaddress))

