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

def qyt_rec_mail(mailserver, mailuser, mailpasswd, id_no):
	#print('Connecting...')
	server = poplib.POP3(mailserver)#连接到邮件服务器
	server.user(mailuser)#邮件服务器用户名
	server.pass_(mailpasswd)#邮件服务器密码
	rec_file_name = []
	try:
		#print(server.getwelcome())#打印服务器欢迎信息
		msgCount, msgBytes = server.stat()#查询邮件数量与字节数
		#print('There are', msgCount, 'mail message in', msgBytes, 'bytes')#打印邮件数量与字节数
		#print(server.list())#打印邮件清单

		for i in range(msgCount):#逐个读取邮件
			hdr, message, octets = server.retr(i + 1)#读取邮件
			str_message = email.message_from_bytes(b'\n'.join(message))#把所有信息加在一起
			for part in str_message.walk():#遍历所有内容
				if part.get_content_maintype() == 'multipart':
					part_dict = part.items()#提取'multipart'内容产生字典
					for key in part_dict:#遍历字典
						if key[0] == 'Subject' and  key[1][-4:] == id_no and key[1][:2] == 'Re':
							#print('get reply！')
							for part in str_message.walk():
								filename = part.get_filename()
								if filename == None:
									try:
										if part.get_payload(decode=1)[:2] == b'y1':
											return True
										elif part.get_payload(decode=1)[:2] == b'n2':
											return False
										else:
											return None
									except Exception as e:
										pass
						else:
							continue
	except Exception as e:
		pass
	finally:
		server.quit()#退出服务器
	#print('Bye.')

if __name__ == '__main__':
	import getpass 
	username = input('请输入用户名: ')
	password = getpass.getpass('请输入密码: ')#读取密码，但是不回显！
	qyt_rec_mail('pop.163.com', username, password)
