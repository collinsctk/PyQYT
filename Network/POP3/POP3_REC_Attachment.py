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
import os
import email
import base64

def qyt_rec_mail(mailserver, mailuser, mailpasswd):
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
			str_message = email.message_from_bytes(b'\n'.join(message))

			for part in str_message.walk():
				#print(part.get_content_type())
				if part.get_content_maintype() == 'multipart':
					part_dict = part.items()
					for key in part_dict:
						if key[0] == 'Subject':
							if re.match('=\?(.*)\?\w\?(.*)=\?',key[1]).groups():
								re_result = re.match('=\?(.*)\?\w\?(.*)\?=',key[1]).groups()
								prefix = '=?' + re_result[0]
								suffix = '?='
								middle = re_result[1]
								decoded = base64.b64decode(middle)
								mail_prefix = str(decoded.decode(re_result[0]))
							else:
								mail_prefix = key[1]
					continue
				filename = part.get_filename()		
				if filename == None:
					mail_file_name = mail_prefix + '_' + str(i) + '.txt'
					fp = open(mail_file_name, 'wb')
					for key in part_dict:
						string = key[0] + '===>' + key[1] + '\n'
						fp.write(string.encode())
					fp.write(b'Main Body ===>')
					fp.write(part.get_payload(decode=1))
					fp.close
				else:
					filename = filename.encode("utf-8").decode()
					mail_file_name = mail_prefix + '_' + str(i) + '+' + filename
					fp = open(mail_file_name, 'wb')
					fp.write(part.get_payload(decode=1))
					fp.close

	finally:
		server.quit()#退出服务器
	print('Bye.')

if __name__ == '__main__':
	import getpass 
	username = input('请输入用户名: ')
	password = getpass.getpass('请输入密码: ')#读取密码，但是不回显！
	qyt_rec_mail('pop.163.com', username, password)
