#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import ftplib
import os

def listftpfile(site, dir='.', user=('anonymous', '1@2.net'), verbose = True):
	if verbose:print('list file')
	remote = ftplib.FTP(site)
	remote.encoding = 'GB18030'
	remote.login(*user)
	remote.cwd(dir)
	lst = remote.nlst() 
	remote.quit()
	return lst

if __name__ == '__main__':
	print(listftpfile('202.100.1.168'))
