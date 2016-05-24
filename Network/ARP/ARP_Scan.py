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
#from GET_IP import get_ip_address #导入获取本机IP地址方法
from PyQYT.Network.Tools.GET_IP_IFCONFIG import get_ip_address_ifconfig #导入获取本机IP地址方法
from PyQYT.Network.Tools.GET_MAC import GET_MAC #导入获取本机MAC地址方法
import optparse

def arp_scan(network_prefix, ifname):
	#localip = get_ip_address(ifname)
	#获取本机IP地址
	localip = get_ip_address_ifconfig(ifname)['ip_address']
	#获取本地MAC地址
	localmac = GET_MAC(ifname)
	#把网络前缀通过'.'分开，并且产生清单prefix
	prefix = network_prefix.split('.')
	#产生一个扫描设备的IP清单
	ip_list = []
	for i in range(254):#0到253
		ipno = prefix[0] + '.' + prefix[1] + '.' + prefix[2] + '.' + str(i+1)#需要把i+1,这样就是1-254
		ip_list.append(ipno) #把IP地址添加到扫描清单
	#发送ARP请求包，并等待响应结果##################################################################################################地址为清单######################配置超时时间################
	result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=ip_list), iface = ifname, timeout = 1, verbose = False)
	#把响应的数据包对，产生为清单
	result_list = result_raw[0].res
	#扫描得到的IP和MAC地址对的清单
	IP_MAC_LIST = []
	for n in range(len(result_list)):#len(result_list)表示响应数据包对的数量
		IP = result_list[n][1][1].fields['psrc'] #提取响应包，ARP头部中的['psrc']字段，这是IP地址
		MAC = result_list[n][1][1].fields['hwsrc'] #提取响应包，ARP头部中的['hwsrc']字段，这是MAC地址
		IP_MAC = [IP, MAC] #把IP和MAC做成清单
		IP_MAC_LIST.append(IP_MAC) #把IP和MAC做成的清单，添加到IP_MAC_LIST这个上一级清单里边

	return IP_MAC_LIST #返回IP_MAC_LIST这个清单

if __name__ == "__main__":
	parser = optparse.OptionParser('用法：\n python3 ARP_Scan.py --network 扫描地址范围 --ifname 扫描接口名')
	parser.add_option('--network', dest = 'network', type = 'string', help = '扫描地址范围')
	parser.add_option('--ifname', dest = 'ifname', type = 'string', help = '扫描接口名')

	(options, args) = parser.parse_args()
	network = options.network
	ifname = options.ifname
	if network == None or ifname == None:
		print(parser.usage)
	else:
		for ip,mac in arp_scan(network, ifname):
			print('IP地址: ' + ip + ' MAC地址: ' + mac)
