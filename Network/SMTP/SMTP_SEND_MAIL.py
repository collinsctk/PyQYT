#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import smtplib, sys, email.utils

def qyt_smtp_sendmail(mailserver, username, password, From, To, Subj):
	Tos = To.split(';')
	Date = email.utils.formatdate()

	text = ('From: %s\nTo: %s\nData: %s\nSubject: %s\n\n' % (From, To, Date, Subj))

	server = smtplib.SMTP(mailserver)
	server.login(username, password)
	failed = server.sendmail(From, Tos, text)
	server.quit()
	if failed:
		print('Falied recipients:', failed)
	else:
		print('No errors.')
	print('Bye.')

if __name__ == '__main__':
	qyt_smtp_sendmail('smtp.163.com', 'collinsctk@163.com', '1a.cisco', 'collinsctk@163.com', 'collinsctk@qytang.com;collinsctk@163.com', 'This is a test mail')
