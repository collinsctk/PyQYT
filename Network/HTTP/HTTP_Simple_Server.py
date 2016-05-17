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
import optparse

def http_simple_server(webdir = '.', webport = 80):
	print('webdir "%s", port %s' % (webdir, webport))
	os.chdir(webdir)#修改本地工作目录，这个目录中应该有index.html
	srvaddr = ('', webport)#绑定本地地址与端口号
	srvobj = HTTPServer(srvaddr, CGIHTTPRequestHandler)#增加动态网页CGI的处理能力
	srvobj.serve_forever()#打开服务器

if __name__ == '__main__':
	parser = optparse.OptionParser('用法：\n python3 HTTP_Simple_Server.py --dirpath 工作目录 --port 工作端口')
	parser.add_option('--dirpath', dest = 'dirpath', type = 'string', help = '工作目录')
	parser.add_option('--port', dest = 'port', type = 'string', help = '工作端口')
	(options, args) = parser.parse_args()
	dirpath = options.dirpath
	port = options.port
	if dirpath == None or port == None:
		print(parser.usage)
	else:
		http_simple_server(dirpath, int(port))