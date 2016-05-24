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

import json

qytangdict = {'Teacher' : [{'name':'chenjiadong', 'age':24}, {'name':'Jiaozhu', 'age':36}],
		  'Deparment' : [{'name' : 'Security', 'Leader' : 'Jiaozhu'}, {'name' : 'DataCenter', 'Leader' : 'Mahaibo'}]
		  }#Python字典对象
qytangjson = json.dumps(qytangdict, indent = 4, separators = (',',':')) #indent为四个空格的缩进，separators分隔符
#把Python对象转换为json对象

qytangjson_decode = json.loads(qytangjson)#把json对象转换为Python对象
print('-'*60)
print('qytangjson:\n%s' % qytangjson)
print('-'*60)
print('qytangjson_decode:\n%s' % qytangjson_decode)
print('-'*60)
