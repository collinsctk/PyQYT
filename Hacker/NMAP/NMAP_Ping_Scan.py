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

import nmap
import sys

def nmap_ping_scan(network_prefix):
	nm = nmap.PortScanner()
	ping_scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -sn')

	host_list = []
	for IP in ping_scan_raw_result['scan']:
		if ping_scan_raw_result['scan'][IP]['status']['state'] == 'up':
			host_list.append(ping_scan_raw_result['scan'][IP]['addresses']['ipv4'])
			#print( '%-20s %5s' % (ping_scan_raw_result['scan'][IP]['addresses']['ipv4'],'is UP'))
	return host_list

if __name__ == '__main__':
	for host in nmap_ping_scan(sys.argv[1]):
		print( '%-20s %5s' % (host,'is UP'))

##################################################################
#[root@Fedora python]# ./nmap_ping_scan.py 172.16.1.0/24
#172.16.1.104         is UP
#172.16.1.101         is UP
#172.16.1.103         is UP
#172.16.1.102         is UP
#172.16.1.107         is UP
#172.16.1.254         is UP
#172.16.1.15          is UP
#172.16.1.12          is UP
