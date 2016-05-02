#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

#varBindTable是个list，元素的个数可能有好多个。它的元素也是list，这个list里的元素是ObjectType，个数只有1个。
errorIndication, errorStatus, errorindex, varBindTable = cmdGen.nextCmd(
	cmdgen.CommunityData('public'),
	cmdgen.UdpTransportTarget(('202.100.1.3',161)),
	'1.3.6.1.2.1.2.2.1.2',
)

if errorIndication:
	print(errorIndication)
elif errorStatus:
	print('%s at %s' % (
			errorStatus.prettyPrint(),
			errorindex and varBinds[int(errorindex)-1][0] or '?'
		)
	)

for varBindTableRow in varBindTable:
	for item in varBindTableRow:
		print(item)
