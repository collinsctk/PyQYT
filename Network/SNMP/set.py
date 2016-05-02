#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorindex, varBinds = cmdGen.setCmd(
	cmdgen.CommunityData('private'),
	cmdgen.UdpTransportTarget(('202.100.1.3',161)),
	('1.3.6.1.2.1.1.5.0',rfc1902.OctetString('SNMPv2R1'))
)

if errorIndication:
	print(errorIndication)
elif errorStatus:
	print('%s at %s' % (
			errorStatus.prettyPrint(),
			errorindex and varBinds[int(errorindex)-1][0] or '?'
		)
	)
for name,val in varBinds:
	print('%s = %s' % (name.prettyPrint(),val.prettyPrint()))
