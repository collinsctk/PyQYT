#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from telnetlib import Telnet
import re
import time

def QYT_TelnetClient(ip, username, password, enable):
	tn = Telnet(ip, 23)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	tn.write(username.encode())
	tn.write(b'\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	tn.write(password.encode())	
	tn.write(b'\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	tn.write(b'enable\n')
	time.sleep(1)
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	tn.write(enable.encode())
	tn.write(b'\n')
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	time.sleep(1)
	tn.write(b'terminal length 0\n')
	tn.write(b'show ver\n')
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	time.sleep(1)
	tn.write(b'exit\n')
	rackreply = tn.expect([],timeout=1)[2].decode().strip()
	print(rackreply)
	tn.close()

if __name__ == "__main__":
	QYT_TelnetClient('202.100.1.3', 'cisco', 'cisco', 'cisco')
