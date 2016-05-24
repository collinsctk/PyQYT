#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import xlrd

def excel_parser(file = 'test.xlsx', sheel_name = 'Sheet1'):
	data = xlrd.open_workbook(file)
	table = data.sheet_by_name(sheel_name)
	nrows = table.nrows
	for i in range(nrows):
		if i == 0:
			print('%-18s %-13s %s' % (table.row_values(i)[0], table.row_values(i)[1], table.row_values(i)[2]))
		else:
			username = table.row_values(i)[0]
			password = table.row_values(i)[1]
			if type(password) is float:
				password = str(int(table.row_values(i)[1]))
			privilege = str(int(table.row_values(i)[2]))
			print('用户:%-15s 密码:%-10s 级别:%s' % (username, password, privilege))

if __name__ == "__main__":
	excel_parser('test.xlsx')
