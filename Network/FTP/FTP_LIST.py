#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import ftplib
import optparse

def listftpfile(hostname, username='anonymous', password='1@2.net', dir='/', timeout=1, verbose = True):
	if verbose:print('罗列一个目录中的所有文件或者目录，并不递归罗列！')
	remote = ftplib.FTP(hostname)#连接站点
	remote.encoding = 'GB18030'#使用中文编码
	remote.login(username, password)#输入用户名和密码进行登录
	remote.cwd(dir)#进入特定目录
	lst = remote.nlst()#罗列目录内容，并且产生清单
	remote.quit()#退出会话
	return lst#返回目录内容的清单

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 FTP_LIST.py --server serverIP --username 用户名 --passwd 密码')
	parser.add_option('--server', dest = 'server', type = 'string', help = 'FTP服务器IP')
	parser.add_option('--username', dest = 'username', type = 'string', help = '用户名')
	parser.add_option('--passwd', dest = 'passwd', type = 'string', help = '密码')
	(options, args) = parser.parse_args()
	server = options.server
	username = options.username
	passwd = options.passwd

	if server == None or username == None or passwd == None:
		print(parser.usage)
	else:
		print(listftpfile(server, username, passwd))