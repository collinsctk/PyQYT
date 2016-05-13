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

from minimumTFTP import Client
import optparse

def qyt_ftpclient(server, filedir, file, operation=1):
	#传递参数服务器地址，本地文件夹，文件名，操作码（1为下载，2为上传）
	tftpClient = Client(server, filedir, file)
	if operation == 1:
		tftpClient.get()
	if operation == 2:
		tftpClient.put()
	print()

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 tftpclient.py --ip server的IP --dirt 本地文件夹 --filename 文件名 --op 操作码')
	parser.add_option('--ip', dest = 'ip', type = 'string', help = 'tftp服务器的IP')
	parser.add_option('--dirt', dest = 'dirt', type = 'string', help = '本地文件夹')
	parser.add_option('--filename', dest = 'filename', type = 'string', help = '文件名')
	parser.add_option('--op', dest = 'op', type = 'string', help = '操作码，1是下载，2是上传')
	(options, args) = parser.parse_args()
	ip = options.ip
	dirt = options.dirt
	filename = options.filename
	op = options.op

	if ip == None or dirt == None or filename == None or filename == None:
		print(parser.usage)
	else:
		qyt_ftpclient(ip, dirt, filename, int(op))
	#qyt_ftpclient('202.100.1.138', '.', 'test-confg', operation=2)
