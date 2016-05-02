#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from ftplib import FTP
import re
def ftp_find(dict, file_type='.py', timeout=1):
	try:
		hostname = dict[0]
		username = dict[1]
		password = dict[2]
		connection = FTP(hostname)
		connection.encoding = 'GB18030'
		connection.login(username, password)
		path = []
		def DirRecursive(dirpath):
			ls = []
			connection.cwd(dirpath)
			connection.retrlines('LIST', ls.append)
			for line in ls:
				patt = '(\d\d-\d\d-\d\d)\s*(\d\d\:\d\d\w\w)\s*(<DIR>|\d*)\s*(\w.*)'
				scan_result = re.match(patt, line)
				date = scan_result.group(1)
				time = scan_result.group(2)
				dir_or_length = scan_result.group(3)
				dir_or_filename = scan_result.group(4)

				if dir_or_length != '<DIR>':
					if dirpath == '/':
						path.append(dirpath + dir_or_filename)
					else:
						path.append(dirpath + '/' + dir_or_filename)
				else:
					if dirpath == '/':
						DirRecursive(dirpath + dir_or_filename)
					else:
						DirRecursive(dirpath + '/' + dir_or_filename)

		DirRecursive('/')
		connection.close()
		filetype_in_ftp = []
		offset = 0 - len(file_type)
		for x in path:
			if x[offset:] == file_type:
				filetype_in_ftp.append(x)

		return filetype_in_ftp
	except Exception as e:
		print(e)

if __name__ == '__main__':
	print(ftp_find(('202.100.1.168', 'ftpuser', 'cisco'), '.py'))