#!/usr/bin/python3.4
# -*- coding=utf-8 -*-

import ftplib
import os

def downloadfile(site, file, user=('anonymous', '1@2.net'), rdir='.', ldir='.', verbose = True):
	if verbose:print('Downloading', file)
	os.chdir(ldir)
	local = open(file, 'wb')
	remote = ftplib.FTP(site)
	remote.encoding = 'GB18030'
	remote.login(*user)
	remote.cwd(rdir)
	remote.retrbinary('RETR ' + file, local.write, 1024)
	remote.quit()
	local.close()
	if verbose: print('Downloading ' + file + ' done.')

if __name__ == '__main__':
	downloadfile('202.100.1.168', 'qyttest.txt')
