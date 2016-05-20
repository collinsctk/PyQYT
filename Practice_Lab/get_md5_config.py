#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import shelve
from Simple_SSH_Client import QYT_SSHClient_SingleCMD
import pickle
import re

def get_md5_config(host_list, username, password,operation=0):
	dict_config = {}
	for host in host_list:
		if operation == 0:
			try:
				run_config = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'show run')
				list_run_config = run_config.decode().split('\r\n')
				location = 0
				host_location = 0
				for i in list_run_config:
					if re.match('.*hostname .*', i):
						host_location = location
					else:
						location += 1
				list_run_config = list_run_config[host_location:]
				run_config = '\r\n'.join(list_run_config)
				md5 = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'verify /md5 system:running-config')
				dict_config[host] = [run_config.encode(),md5.strip()[-32:]]
			except Exception as e:
				print('%stErrorn %s'%(host,e))
		elif operation == 1:
			try:
				run_config = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'show run')
				list_run_config = run_config.decode().split('\r\n')
				location = 0
				host_location = 0
				for i in list_run_config:
					if re.match('.*hostname .*', i):
						host_location = location
					else:
						location += 1
				list_run_config = list_run_config[host_location:]
				run_config = '\r\n'.join(list_run_config)
				#md5 = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'verify /md5 system:running-config')
				dict_config[host] = run_config.encode()
			except Exception as e:
				print('%stErrorn %s'%(host,e))
		elif operation == 2:
			try:
				#run_config = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'show run')
				md5 = QYT_SSHClient_SingleCMD(host, 'admin', 'cisco', 'verify /md5 system:running-config')
				dict_config[host] = md5.strip()[-32:]
			except Exception as e:
				print('%stErrorn %s'%(host,e))
		else:
			print('操作码传入错误！')
	return dict_config

if __name__ == '__main__':
	print(get_md5_config(['202.100.1.1','202.100.12.2'], 'admin', 'cisco',operation=2))