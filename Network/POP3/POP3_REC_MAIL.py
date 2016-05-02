#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import poplib, getpass, sys
import re

def qyt_rec_mail(mailserver, mailuser, mailpasswd, mailprefix):
	print('Connecting...')
	server = poplib.POP3(mailserver)
	server.user(mailuser)
	server.pass_(mailpasswd)

	try:
		print(server.getwelcome())
		msgCount, msgBytes = server.stat()
		print('There are', msgCount, 'mail message in', msgBytes, 'bytes')
		print(server.list())

		for i in range(msgCount):
			hdr, message, octets = server.retr(i + 1)
			mail_file_name = mailprefix + '_' + str(i+1) + '.txt'
			mail_file = open(mail_file_name, 'wb')
			for line in message:
				mail_file.write(line)
			mail_file.close()
			print(mail_file_name + ' Recieved!!!')
	finally:
		server.quit()
	print('Bye.')

if __name__ == '__main__':
	qyt_rec_mail('pop.163.com', 'collinsctk@163.com', '1a.cisco', 'test1')