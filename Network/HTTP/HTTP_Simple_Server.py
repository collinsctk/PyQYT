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

import os, sys
from http.server import HTTPServer, CGIHTTPRequestHandler

def http_simple_server(webdir = '.', webport = 80):
	print('webdir "%s", port %s' % (webdir, webport))
	os.chdir(webdir)#修改本地工作目录，这个目录中应该有index.html
	srvaddr = ('', webport)#绑定本地地址与端口号
	srvobj = HTTPServer(srvaddr, CGIHTTPRequestHandler)#增加动态网页CGI的处理能力
	srvobj.serve_forever()#打开服务器

if __name__ == '__main__':
	try:
		if len(sys.argv) == 1:
			http_simple_server()#如果没有参数，就直接用默认参数启动服务器
		elif len(sys.argv) == 2:
			webdir = sys.argv[1]#如果有一个参数，这个参数为网页的根目录
			http_simple_server(webdir = webdir)
		elif len(sys.argv) == 3:
			webdir = sys.argv[1]#如果有两个参数，第一个参数为网页的根目录
			webport = int(sys.argv[2])#第二个参数为web服务器的端口号
			http_simple_server(webdir = webdir, webport = webport)
		else:
			print('参数过多！只需要两个参数，第一为HTTP服务器主目录，第二个为端口号！')#如果参数过多打印错误信息
	except Exception as e:
		print(e)
		print('具体格式为:"./HTTP_Simple_Server [HTTP服务主目录] [HTTP服务器端口号]"')#如果其他故障，打印帮助信息