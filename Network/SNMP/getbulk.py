#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorindex, varBindTable = cmdGen.bulkCmd(
	cmdgen.CommunityData('public'),
	cmdgen.UdpTransportTarget(('202.100.1.3',161)),
	0,25,
	'1.3.6.1.2.1.2.2.1.2',
)
#0为non-repeaters 和  25为max-repetitions
if errorIndication:
	print(errorIndication)
elif errorStatus:
	print('%s at %s' % (
			errorStatus.prettyPrint(),
			errorindex and varBinds[int(errorindex)-1][0] or '?'
		)
	)

for varBindTableRow in varBindTable:
	for name, val in varBindTableRow:
		print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))