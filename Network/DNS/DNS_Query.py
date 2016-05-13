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
import re
import optparse

def dns_query(dns_name):
	dns_result = sr1(IP(dst="114.114.114.114")/UDP()/DNS(id=168,qr=0,opcode=0,rd=1,qd=DNSQR(qname=dns_name)), verbose=False)
	#id标识字段（匹配请求与回应），qr等于0表示查询报文，opcode为0表示标准查询，rd为1表示期望递归
	layer = 1
	while True:#不太确定DNSRR到底有几组！！！
		try:
			if dns_result.getlayer(DNS).fields['an'][layer].fields['type'] == 1: #A记录
				dns_result_ip = dns_result.getlayer(DNS).fields['an'][layer].fields['rdata']
				#每一层就是一个记录，但是不一定是A，可能是CNAME！
				print('域名: %-18s 对应的IP地址: %s' % (dns_name, dns_result_ip))#找到IP地址并打印
			layer += 1
		except:#如果超出范围就跳出循环
			break

if __name__ == "__main__":
	parser = optparse.OptionParser('用法：\n python3 DNS_Query.py --domainName 域名')
	parser.add_option('--domainName', dest = 'domainName', type = 'string', help = '要被解析的域名')
	(options, args) = parser.parse_args()
	domainName = options.domainName
	if domainName == None:
		print(parser.usage)
	else:
		dns_query(domainName)

