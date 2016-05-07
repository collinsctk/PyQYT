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
import time
import sys

def QYT_SSHClient_MultiCMD(ip, username, password, *cmds):
	ssh=paramiko.SSHClient()#创建SSH Client
	ssh.load_system_host_keys()#加载系统SSH密钥
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())#添加新的SSH密钥
	ssh.connect(ip,port=22,username=username,password=password,timeout=5,compress=True)#SSH连接

	chan=ssh.invoke_shell()#激活交互式shell
	time.sleep(1)
	x = chan.recv(2048).decode()#接收回显信息

	for cmd in cmds:#读取命令
		chan.send(cmd.encode())#执行命令，注意字串都需要编码为二进制字串
		chan.send(b'\n')#一定要注意输入回车
		time.sleep(2)#由于有些回显可能过长，所以可以考虑等待更长一些时间
		x = chan.recv(40960).decode()#读取回显，有些回想可能过长，请把接收缓存调大
		print(x)#打印回显
		
	chan.close()#退出交互式shell
	ssh.close()#退出ssh会话

if __name__ == '__main__':
	QYT_SSHClient_MultiCMD('202.100.1.3', 'cisco', 'cisco', 'term length 0', 'show ver', 'show ip inter brie')