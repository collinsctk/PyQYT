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

from telnetlib import Telnet
#import re,可以使用正则表达式匹配回显，然后做判断，决定下一步的操作
import time

def QYT_TelnetClient(ip, username, password, cmd):
	tn = Telnet(ip, 23)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()#读取回显
	#print(rackreply)#打印回显
	tn.write(username.encode())#任何字串都需要转成二进制字串
	tn.write(b'\n')#注意一定要打回车
	time.sleep(1)#在命令之间留出一定的时间间隔！否则路由器可能反应不过来
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	#print(rackreply)
	tn.write(password.encode())	
	tn.write(b'\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	#print(rackreply)

	tn.write('terminal length 0'.encode() + b'\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	#print(rackreply)

	tn.write(cmd.encode() + b'\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	#print(rackreply)
	result = rackreply
	time.sleep(1)
	tn.write(b'exit\n')
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	#print(rackreply)
	tn.close()
	return result

if __name__ == "__main__":
	result = QYT_TelnetClient('202.100.1.254', 'admin', 'cisco','show mac address-table dynamic')
	print(result)