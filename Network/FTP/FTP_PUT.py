#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import ftplib
import os

def putfile(site, file, user=('anonymous', '1@2.net'), rdir='.', ldir='.', verbose = True):
	if verbose:print('Uploading', file)
	os.chdir(ldir)
	local = open(file, 'rb')
	remote = ftplib.FTP(site)
	remote.encoding = 'GB18030'
	remote.login(*user)
	remote.cwd(rdir)
	remote.storbinary('STOR ' + file, local, 1024)
	remote.quit()
	local.close()
	if verbose: print('Upload done.')

if __name__ == '__main__':
	putfile('202.100.1.168', 'FTP_LIST.py', user=('ftpuser', 'cisco'))
