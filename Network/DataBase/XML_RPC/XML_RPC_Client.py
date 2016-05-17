#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

#参考原始文档
#https://docs.python.org/3.1/library/xmlrpc.client.html#example-of-client-and-server-usage

import datetime
import xmlrpc.client

proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:8000/")
print("3 is even: %s" % str(proxy.is_even(3)))#远程执行proxy上的is_even函数
print("100 is even: %s" % str(proxy.is_even(100)))#远程执行proxy上的is_even函数

today = proxy.today()#远程执行proxy上的today函数
#convert the ISO8601 string to a datetime object
converted = datetime.datetime.strptime(today.value, "%Y%m%dT%H:%M:%S")
print("Today: %s" % converted.strftime("%d.%m.%Y, %H:%M"))

