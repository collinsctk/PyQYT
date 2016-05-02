#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import json

JSON_File = open('test.json', 'r')
JSON_LOAD = json.load(JSON_File)
for i in JSON_LOAD:
	print('-'*50)
	if i == 'Deparment':
		print('部门与主管')
		print('+'*50)
		for x in JSON_LOAD[i]:
			print('    部门名: %-12s ==> 部门主管: %s' %(x['name'], x['Leader'] ))
	elif i == 'Teacher':
		print('老师与年龄')
		print('+'*50)
		for x in JSON_LOAD[i]:
			print('    老师名: %-12s ==> 年龄: %s' %(x['name'], x['age'] ))



