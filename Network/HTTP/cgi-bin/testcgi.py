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

import cgi

form = cgi.FieldStorage()#读取客户输入
username = cgi.escape(form['user'].value)#读取客户输入的姓名
age = cgi.escape(form['age'].value)#读取客户输入的年龄
#打印HTML网页，注意格式！
print('Content-type:text/html\n')
print('<HTML>')
print('<title>CGI响应测试页面</title>')
print('<BODY>')
print('<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />')
print('<H1>你的姓名: ' + username + '</H1>')
print('<H1>你的年龄: ' + age + '</H1>')
print('</BODY></HTML>')