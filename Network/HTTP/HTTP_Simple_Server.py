#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import os, sys
from http.server import HTTPServer, CGIHTTPRequestHandler

def http_simple_server(webdir = '.', webport = 80):
	print('webdir "%s", port %s' % (webdir, webport))
	os.chdir(webdir)
	srvaddr = ('', webport)
	srvobj = HTTPServer(srvaddr, CGIHTTPRequestHandler)
	srvobj.serve_forever()

if __name__ == '__main__':
	try:
		if len(sys.argv) == 1:
			http_simple_server()
		elif len(sys.argv) == 2:
			webdir = sys.argv[1]
			http_simple_server(webdir = webdir)
		elif len(sys.argv) == 3:
			webdir = sys.argv[1]
			webport = int(sys.argv[2])
			http_simple_server(webdir = webdir, webport = webport)
		else:
			print('参数过多！只需要两个参数，第一为HTTP服务器主目录，第二个为端口号！')
	except Exception as e:
		print(e)
		print('具体格式为:"./HTTP_Simple_Server [HTTP服务主目录] [HTTP服务器端口号]"')