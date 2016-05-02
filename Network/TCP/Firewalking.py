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

conf.route.add(net='10.1.1.0/24',gw='202.100.1.10')#单独为Scapy添加路由条目，超越linux的路由表

#print(conf.route)#打印Scapy的路由表

def Firewalking(dstaddr, ttlno, lport, hport):#定义方法，传入目的地址，TTL值，扫描开始的低端口，扫描结束的高端口
	#发送并接收回应，#TTL需要确保抵达防火墙时整好为0#目的端口为元组（低端口，高端口），inter为发送间隔（太快防火墙会拒绝），timeout是等待回应的超时时间！
	result_raw = sr(IP(dst=dstaddr, ttl=ttlno)/TCP(dport=(lport,hport)), inter=1, timeout=5, verbose=False)
	#注意必须目的地址真实存在，流量确实被ACL放过，TTL抵达防火墙时为0，测试才能成功！！！
	#把收到响应的数据包对，产生清单！！！
	result_list = result_raw[0].res
	for i in range(len(result_list)):#遍历整个清单的内容
		icmp_fields = result_list[i][1]['ICMP'].fields#提取响应数据包的ICMP字段，并产生字典！
		ip_fields = result_list[i][1]['IP'].fields#提取响应数据包的IP字段，并产生字典！
		scan_fields = result_list[i][0]['TCP'].fields#提取发送数据包的TCP字段，并产生字典！
		if icmp_fields['type'] == 11:#如果ICMP类型为11，TTL超时！
			#打印防火墙地址与开放端口号
			print('Firewall is at ' + ip_fields['src'] + ' Port: ' + str(scan_fields['dport']) + ' is Open!!!')

if __name__ == '__main__':
	Firewalking('10.1.1.1', 0, 20, 40)
