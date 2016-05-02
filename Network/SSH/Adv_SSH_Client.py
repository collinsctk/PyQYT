#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import paramiko

import paramiko
import time
import sys

def QYT_SSHClient_MultiCMD(ip, username, password, *cmds):
	ssh=paramiko.SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(ip,port=22,username=username,password=password,compress=True)

	chan=ssh.invoke_shell()
	time.sleep(1)
	x = chan.recv(2048).decode()

	for cmd in cmds:
		chan.send(cmd.encode())
		chan.send(b'\n')
		time.sleep(2)
		x = chan.recv(40960).decode()
		print(x)
		
	chan.close()
	ssh.close()

if __name__ == '__main__':
	QYT_SSHClient_MultiCMD('202.100.1.3', 'admin', 'cisco', 'term length 0', 'show ver', 'show ip inter brie')