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

import re
import smtplib, email.utils
from email.mime.multipart import MIMEMultipart  
from email.mime.text import MIMEText  
from email.mime.application import MIMEApplication


def qyt_smtp_attachment(mailserver, username, password, From, To, Subj, Main_Body, files=None):
	Tos = To.split(';')#把多个邮件接受者通过';'分开
	Date = email.utils.formatdate()#格式化邮件时间
	msg = MIMEMultipart() 
	msg["Subject"] = Subj  
	msg["From"]    = From  
	msg["To"]      = To
	msg["Date"]    = Date

	part = MIMEText(Main_Body)  
	msg.attach(part)

	if files:
		for file in files:
			part = MIMEApplication(open(file,'rb').read())
			part.add_header('Content-Disposition', 'attachment', filename=file)  
			msg.attach(part) 

	server = smtplib.SMTP(mailserver)#连接邮件服务器
	server.login(username, password)#通过用户名和密码登录邮件服务器
	failed = server.sendmail(From, Tos, msg.as_string())#发送邮件
	server.quit()#退出会话
	if failed:
		print('Falied recipients:', failed)#如果出现故障，打印故障原因！
	else:
		print('邮件已经成功发出！')#如果没有故障发生，打印‘No errors.’！
	#print('Bye.')

if __name__ == '__main__':
	import getpass 
	username = input('请输入用户名: ')
	password = getpass.getpass('请输入密码: ')#读取密码，但是不回显！
	subject = input('请输入邮件主题: ')
	Main_Body = input('请输入邮件正文: ')
	files_input = input("输入文件名用','分开: ")
	if re.match('\s*\w+', files_input):
		files = files_input.split(',')
	else:
		files = None
	qyt_smtp_attachment('smtp.163.com',
					  	username,
					  	password, 
					  	'collinsctk@163.com',
					  	'collinsctk@qytang.com;collinsctk@163.com',
					  	subject,
					  	Main_Body,
					  	files)