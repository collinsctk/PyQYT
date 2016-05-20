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

import paramiko

def QYT_SSHClient_SingleCMD(ip, username, password, cmd):
	try:
		ssh = paramiko.SSHClient()#创建SSH Client
		ssh.load_system_host_keys()#加载系统SSH密钥
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())#添加新的SSH密钥
		ssh.connect(ip,port=22,username=username,password=password,timeout=5,compress=True)#SSH连接
		stdin,stdout,stderr = ssh.exec_command(cmd)#执行命令
		x = stdout.read()#读取回显
		return x
		ssh.close()
	except Exception as e:
		print('%stErrorn %s'%(ip,e))

if __name__ == '__main__':
	print(QYT_SSHClient_SingleCMD('202.100.12.2', 'admin', 'cisco', 'show run'))
