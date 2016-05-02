#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from minimumTFTP.minimumTFTP import Client

def qyt_ftpclient(server, filedir, file, operation=1):
	tftpClient = Client(server, filedir, file)
	if operation == 1:
		tftpClient.get()
	if operation == 2:
		tftpClient.put()
	print()

if __name__ == '__main__':
	#qyt_ftpclient('202.100.1.138', '.', 'snmpv2r1-confg', operation=1)
	qyt_ftpclient('202.100.1.138', '.', 'test-confg', operation=2)