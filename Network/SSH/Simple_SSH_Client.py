#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import paramiko

def QYT_SSHClient_SingleCMD(ip, username, password, cmd):
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip,22,username,password,timeout=5)
		stdin,stdout,stderr = ssh.exec_command(cmd)
		x = stdout.read().decode()
		print(x)
		ssh.close()
	except:
		print('%stErrorn'%(ip))

if __name__ == '__main__':
	QYT_SSHClient_SingleCMD('202.100.1.3', 'admin', 'cisco', 'show ver')
