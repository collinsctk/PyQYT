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

import poplib, getpass, sys
import re

def qyt_rec_mail(mailserver, mailuser, mailpasswd, mailprefix):
	print('Connecting...')
	server = poplib.POP3(mailserver)#连接到邮件服务器
	server.user(mailuser)#邮件服务器用户名
	server.pass_(mailpasswd)#邮件服务器密码

	try:
		print(server.getwelcome())#打印服务器欢迎信息
		msgCount, msgBytes = server.stat()#查询邮件数量与字节数
		print('There are', msgCount, 'mail message in', msgBytes, 'bytes')#打印邮件数量与字节数
		print(server.list())#打印邮件清单

		for i in range(msgCount):#逐个读取邮件
			hdr, message, octets = server.retr(i + 1)#读取邮件
			mail_file_name = mailprefix + '_' + str(i+1) + '.txt'#本地邮件文件名
			mail_file = open(mail_file_name, 'wb')#创建本地邮件文件
			for line in message:
				mail_file.write(line)#把邮件写入本地邮件文件
			mail_file.close()#写入完毕，关闭本地邮件文件
			print(mail_file_name + ' Recieved!!!')
	finally:
		server.quit()#退出服务器
	print('Bye.')

if __name__ == '__main__':
	import getpass 
	username = input('请输入用户名: ')
	password = getpass.getpass('请输入密码: ')#读取密码，但是不回显！
	mailprefix = input('邮件前缀: ')
	qyt_rec_mail('pop.163.com', username, password, mailprefix)
