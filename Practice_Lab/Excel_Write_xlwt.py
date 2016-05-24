#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import xlwt
dict_excel = {'test123':('cisco123',15), 'test456':('cisco456',1), 'test789':('cisco789',1)}

def excel_write(file = 'write.xls', sheel_name = 'Sheet1', write_dict = dict_excel):
	wbk = xlwt.Workbook(encoding='utf-8', style_compression=0)
	sheet = wbk.add_sheet('sheet 1', cell_overwrite_ok=True)
	sheet.write(0, 0, '用户')
	sheet.write(0, 1, '密码')
	sheet.write(0, 2, '级别')
	row = 1
	for x,y in dict_excel.items():
		sheet.write(row, 0, x)
		sheet.write(row, 1, y[0])
		sheet.write(row, 2, y[1])
		row += 1
	wbk.save(file)

if __name__ == "__main__":	
	excel_write()
