#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import json

staff1 = {'Teacher' : [{'name':'chenjiadong', 'age':24}, {'name':'Jiaozhu', 'age':36}],
		  'Deparment' : [{'name' : 'Security', 'Leader' : 'Jiaozhu'}, {'name' : 'DataCenter', 'Leader' : 'Mahaibo'}]
		  }
encodestaff1 = json.dumps(staff1, indent = 4, separators = (',',':')) #indent为四个空格的缩进，separators分隔符
decodestaff1 = json.loads(encodestaff1)
print('-'*60)
print('encodestaff1:\n%s' % encodestaff1)
print('-'*60)
print('decodestaff1:\n%s' % decodestaff1)
print('-'*60)
