#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import sys, http.client

def qytang_http_client(server, os = 1, port = 80, filename = '/', showlines = 6):
	print(server, filename)
	server = http.client.HTTPConnection(server, port)
	#putrequest中可以指定请求的方式，不止GET，支持的方法有：
	#GET, POST, PUT, HEAD, DELETE, OPTIONS, TRACE, CONNECT, LINK, UNLINK
	#例如：
	#server.putrequest('POST', filename)
	#server.putrequest('OPTIONS', filename)
	#server.putrequest('PUT', filename)
	#server.putrequest('HEAD', filename)
	#等等
	server.putrequest('GET', filename)

	#putheader可以向HTTP的头部添加任何自定义的变量及其对应的值
	#如server.putheader('myVar', 'myVal')，这样就会像头部中添加myVar变量，它的值是myVal
	#server.putheader('Accept', 'text/html')
	if os == 1:#PC
		server.putheader('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)')
	elif os == 2:#Android
		server.putheader('User-Agent', 'Mozilla/5.0(Linux; U; Android 2.2; en-gb; LG-P500 Build/FRF91) AppleWebKit/533.0 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1')
	elif os == 3:#iOS
		server.putheader('User-Agent', 'Apple-iPhone7C2/1202.466')
	#调用endheaders之后，就不能向头部继续添加字段了
	server.endheaders()

	#如果请求没有被发送出去，或者上一个response没有被处理，那么会产生异常
	#获取到的信息是以bytes字符串
	#所以，如果后面要用html.parser来解析html，那么就要将bytes字符串转换成str字符串
	reply = server.getresponse()
	if reply.status != 200:
		print('Error sending request!\n', 'status: ', reply.status, '\n reason: ', reply.reason)
	else:
		data = reply.readlines()
		reply.close()
		for line in data[:showlines]: print(line)

if __name__ == '__main__':
	qytang_http_client('www.baidu.com', os = 3)
