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
from xmlrpc.server import SimpleXMLRPCServer
import xmlrpc.client

def is_even(n):#创建函数，判断奇数偶数
    return n%2 == 0

def today():#创建函数，返回时间
    today = datetime.datetime.today()
    return xmlrpc.client.DateTime(today)

server = SimpleXMLRPCServer(("127.0.0.1", 8000))
print("Listening on port 8000...")
server.register_multicall_functions()#启动多函数注册功能！
server.register_function(is_even, "is_even")#注册函数，名字为"is_even"
server.register_function(today, "today")#注册函数，名字为"today"
server.serve_forever()#运行服务器
