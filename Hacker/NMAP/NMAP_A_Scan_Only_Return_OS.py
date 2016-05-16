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

#!/usr/bin/python3.4
# -*- coding=utf-8 -*-

import nmap
import sys
import re
def nmap_A_scan(network_prefix):
	nm = nmap.PortScanner()
	scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -A')
	os_dict = {}
	for host in scan_raw_result['scan']:
		if scan_raw_result['scan'][host]['status']['state'] == 'up':
			for os in scan_raw_result['scan'][host]['osmatch']:
				os_dict[scan_raw_result['scan'][host]['addresses']['ipv4']] = re.split(',|or', os['name'])

	for x,y in os_dict.items():
		y = [i.strip() for i in y]
		newy = []
		for z in y:
			if z != '':
				newy.append(z)
		os_dict[x] = newy

	return os_dict

if __name__ == '__main__':
	print(nmap_A_scan(sys.argv[1]))