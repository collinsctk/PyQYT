#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from Excel_Write_openpyxl import excel_write
from Simple_SSH_Client import QYT_SSHClient_SingleCMD
import re

def excel_ios_user_to_excel(ip, username, password, excelfile):
	show_run = QYT_SSHClient_SingleCMD(ip, username, password, 'sh run | in username')
	show_run_list = show_run.decode().split('\r\n')
	user_dict = {}
	for x in show_run_list:
		#print(x)
		if re.match('username (\w+) privilege (\d+) password \w (\w+)', x):
			re_result = re.match('username (\w+) privilege (\d+) password \w (\w+)', x).groups()
			user_dict[re_result[0]] = re_result[2],int(re_result[1])
		elif re.match('username (\w+) password \w (\w+)', x):
			re_result = re.match('username (\w+) password \w (\w+)', x).groups()
			user_dict[re_result[0]] = re_result[1],1
	excel_write(file = excelfile, sheel_name = ip, write_dict = user_dict)

if __name__ == "__main__":
	excel_ios_user_to_excel('202.100.1.1', 'admin', 'cisco', 'iosuser.xlsx')
