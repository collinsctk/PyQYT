#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import ftplib
import os

def putfile(hostname, file, username='anonymous', password='1@2.net', rdir='.', ldir='.', verbose = True):
	if verbose:print('上传文件:', file)
	os.chdir(ldir)#切换本地工作目录
	local = open(file, 'rb')#读取本地文件
	remote = ftplib.FTP(hostname)#连接站点
	remote.encoding = 'GB18030'#使用中文编码
	remote.login(username, password)#输入用户名和密码进行登录
	remote.cwd(rdir)#切换FTP目录
	remote.storbinary('STOR ' + file, local, 1024)#上传文件
	remote.quit()#退出会话
	local.close()#关闭本地文件
	if verbose: print('上传文件:' + file + ' 结束！')

if __name__ == '__main__':
	putfile('202.100.1.168', 'FTP_LIST.py', username='ftpuser', password='cisco')
