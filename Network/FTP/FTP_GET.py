#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import ftplib
import os
import optparse

def downloadfile(hostname, file, username='anonymous', password='1@2.net', rdir='.', ldir='.', verbose = True):
	if verbose:print('下载文件:', file)
	os.chdir(ldir)#切换本地工作目录
	local = open(file, 'wb')#创建文件
	remote = ftplib.FTP(hostname)#连接站点
	remote.encoding = 'GB18030'#使用中文编码
	remote.login(username, password)#输入用户名和密码进行登录
	remote.cwd(rdir)#切换FTP目录
	remote.retrbinary('RETR ' + file, local.write, 1024)#下载FTP文件，并且写入到本地文件
	remote.quit()#退出会话
	local.close()#关闭本地文件
	if verbose: print('下载文件:' + file + ' 结束！')

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 FTP_GET.py --server serverIP --username 用户名 --passwd 密码 --filename 文件名')
	parser.add_option('--server', dest = 'server', type = 'string', help = 'FTP服务器IP')
	parser.add_option('--username', dest = 'username', type = 'string', help = '用户名')
	parser.add_option('--passwd', dest = 'passwd', type = 'string', help = '密码')
	parser.add_option('--filename', dest = 'filename', type = 'string', help = '文件名')
	(options, args) = parser.parse_args()
	server = options.server
	username = options.username
	passwd = options.passwd
	filename = options.filename

	if server == None or username == None or passwd == None or filename == None:
		print(parser.usage)
	else:
		downloadfile(server, filename, username, passwd)