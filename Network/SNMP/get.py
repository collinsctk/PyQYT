#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.hlapi import *

#varBinds是列表，列表中的每个元素的类型是ObjectType（该类型的对象表示MIB variable）
errorIndication, errorStatus, errorindex, varBinds = next(
	getCmd(SnmpEngine(),
		  CommunityData('public'),
		  UdpTransportTarget(('202.100.1.3',161)),
		  ContextData(),
		  ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
		  ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))
		  )
	)

if errorIndication:
	print(errorIndication)
elif errorStatus:
	print('%s at %s' % (
			errorStatus.prettyPrint(),
			errorindex and varBinds[int(errorindex)-1][0] or '?'
		)
	)

for varBind in varBinds:
	print(varBind)
