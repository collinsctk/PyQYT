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

#定义方法，需要传入目的地址（hostname），扫描开始的低端口号（lport）和结束的高端口号（hport）！
def syn_scan_final(hostname,lport,hport):
	#发送SYN包，并且等待回应##############目的端口可以为元组(lport,hport)##flag为SYN（S）#########
	result_raw = sr(IP(dst=hostname)/TCP(dport=(int(lport),int(hport)),flags="S"), verbose = False)
	result_list = result_raw[0].res #把收到响应的数据包对，产生清单！！！
	for i in range(len(result_list)):#遍历整个清单的内容
		tcpfields = result_list[i][1][1].fields#把每一个接收数据包的TCP头部产生字典
		if tcpfields['flags'] == 18:#如果flags为18（ACK为16，SYN为2）
			#打印这个回应SYN+ACK包的TCP的源端口为开放状态！
			print('端口号: ' + str(tcpfields['sport']) + '  is Open!!!')

if __name__ == '__main__':
	host = input('请你输入扫描主机的IP地址: ')
	port_low = input('请你输入扫描端口的最低端口号: ')
	port_high = input('请你输入扫描端口的最高端口号: ')
	syn_scan_final(host,port_low,port_high)