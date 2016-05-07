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

import sys, http.client

def qytang_http_client(server, port = 80, filename = '/', showlines = 6):
	server = http.client.HTTPConnection(server, port)#连接到服务器与响应端口号
	#putrequest中可以指定请求的方式，不止GET，支持的方法有：
	#GET, POST, PUT, HEAD, DELETE, OPTIONS, TRACE, CONNECT, LINK, UNLINK
	#例如：
	#server.putrequest('POST', filename)
	#server.putrequest('OPTIONS', filename)
	#server.putrequest('PUT', filename)
	#server.putrequest('HEAD', filename)
	#等等......
	server.putrequest('GET', filename)#method与读取的文件名，'/'为默认网页文件，例如index.html

	#putheader可以向HTTP的头部添加任何自定义的变量及其对应的值
	#如server.putheader('myVar', 'myVal')，这样就会像头部中添加myVar变量，它的值是myVal
	server.putheader('Accept', 'text/html')#可以接受的返回信息

	#调用endheaders之后，就不能向头部继续添加字段了
	server.endheaders()

	#如果请求没有被发送出去，或者上一个response没有被处理，那么会产生异常
	#获取到的信息是以bytes字符串
	#所以，如果后面要用html.parser来解析html，那么就要将bytes字符串转换成str字符串
	reply = server.getresponse()#读取服务器的回应
	if reply.status != 200:#如果不是200！200表示OK，非200表示出现问题，此处打印问题原因！
		print('Error sending request!\n', 'status: ', reply.status, '\n reason: ', reply.reason)
	else:#如果为200，表示一切正常！
		data = reply.readlines()#逐行读取服务器响应信息
		reply.close()
		for line in data[:showlines]: print(line)#打印‘showlines’数量行数的信息！

if __name__ == '__main__':
	qytang_http_client('www.qytang.com')