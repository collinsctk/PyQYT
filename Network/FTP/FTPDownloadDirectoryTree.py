#本代码运行在python2环境下！！

import sys
import ftllib
import os
from ftplib import FTP

ftp = FTP("10.1.1.125")
ftp.login("anonymous", "password")

def downloadFiles(path, destination):
	try:
		ftp.cwd(path)
		os.chdir(destination)
		os.mkdir(destination[0:len(destination)-1]+path)
	except OSError:
		pass
	except ftplib.error_perm:
		print 'error: could not change to '+path
		sys.exit("ending session")

	filelist = ftp.nlst()

	for file in filelist:
		try:
			ftp.cwd(path+file+'/')
			downloadFiles(path+file+'/',destination)
		except ftplib.error_perm:
			newDestination = destination[0:len(destination)-1]+path
			os.chdir(newDestination)
			try:
				ftp.retrbinary("RETR "+path+file, open(os.path.join(newDestination, file), "wb").write)
			except ftplib.error_perm, e:
				print file
				print e

	return

source = "/dir/"
dest = "/home/cjd/backups"
downloadFiles(source, dest)
