#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import cgi

form = cgi.FieldStorage()
username = cgi.escape(form['user'].value)
age = cgi.escape(form['age'].value)
print('Content-type:text/html\n')
print('<HTML>')
print('<title>Reply Page</title>')
print('<BODY>')
print('<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />')
print('<H1>Your name: ' + username + '</H1>')
print('<H1>Your age: ' + age + '</H1>')
print('</BODY></HTML>')