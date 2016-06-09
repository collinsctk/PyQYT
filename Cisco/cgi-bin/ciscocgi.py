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
objname = cgi.escape(form['objname'].value)
objip = cgi.escape(form['objip'].value)
natip = cgi.escape(form['natip'].value)
tcpport = cgi.escape(form['tcpport'].value)

#objname = 'new_obj_515'
#objip = '10.1.1.155'
#natip = '202.100.1.155'
#tcpport = '80'

from PyQYT.Cisco.ASA_REST_Object_Network_Add import asa_object_network_add
from PyQYT.Cisco.ASA_REST_ACL import asa_acl
from PyQYT.Cisco.ASA_REST_NAT_Add import asa_nat_add
from io import StringIO

def print_result(final_result):
	print('Content-type:text/html\n')
	print('<HTML>')
	print('<title>CGI响应测试页面</title>')
	print('<BODY>')
	print('<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />')
	print('<img src="../Logo.jpg" width="165" height="165" />')
	print('<H1>' + final_result + '</H1>')
	print('</BODY></HTML>')


natobjname = objname + '_nat'

obj_result_final = 'init'
obj_nat_result_final = 'init'
obj_result_final = 'init'
acl_result_final = 'init'
nat_result_final = 'init'

tmp = sys.stdout
obj_result = StringIO()
sys.stdout = obj_result
asa_object_network_add('192.168.1.10','admin','cisco',objname,objip)
sys.stdout = tmp
obj_result_final = obj_result.getvalue().strip()

tmp = sys.stdout
obj_nat_result = StringIO()
sys.stdout = obj_nat_result
asa_object_network_add('192.168.1.10','admin','cisco',natobjname,natip)
sys.stdout = tmp
obj_nat_result_final = obj_nat_result.getvalue().strip()

print(obj_result_final)
print(obj_nat_result_final)
if obj_result_final == "b''" and obj_nat_result_final == "b''":
	tmp = sys.stdout
	acl_result = StringIO()
	sys.stdout = acl_result
	asa_acl('192.168.1.10','admin','cisco',1,'tcp','any',objname,int(tcpport))
	sys.stdout = tmp
	acl_result_final = acl_result.getvalue().strip()

else:
	if obj_result_final != "b''":
		final_result = "网络Object创建故障！" + obj_result_final
	else:
		final_result = "网络Object创建故障！" + obj_nat_result_final
	print_result(final_result)
	sys.exit(1)

print(acl_result_final)

if acl_result_final == "b''":
	tmp = sys.stdout
	nat_result = StringIO()
	sys.stdout = nat_result
	asa_nat_add('192.168.1.10','admin','cisco',objname,natobjname)
	sys.stdout = tmp
	nat_result_final = nat_result.getvalue().strip()

else:
	final_result = "访问控制列表创建故障！" + acl_result_final
	print_result(final_result)
	sys.exit(1)

print(nat_result_final)

if nat_result_final == "b''":
	final_result = "整个策略完全成功！"
	print_result(final_result)
	sys.exit(1)
else:
	final_result = "NAT创建故障！" + nat_result_final
	print_result(final_result)
	sys.exit(1)

