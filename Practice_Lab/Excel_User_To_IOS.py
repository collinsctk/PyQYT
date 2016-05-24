#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from Excel_Parser_openpyxl_Return_dict import excel_parser_return_dict
from SSH_Client_CMDS import QYT_SSHClient_MultiCMD

def excel_user_to_ios(ip, username, password, excelfile):
	user_dict = excel_parser_return_dict(excelfile)
	cmds = ['configure terminal']
	for x,y in user_dict.items():
		cmd = 'username ' + x + ' privilege ' + str(y[1]) + ' password ' + str(y[0])
		cmds.append(cmd)
	QYT_SSHClient_MultiCMD(ip, username, password, cmds)

if __name__ == "__main__":
	excel_user_to_ios('202.100.1.1', 'admin', 'cisco', 'test.xlsx')
