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

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorindex, varBindTable = cmdGen.bulkCmd(
	cmdgen.CommunityData('public'),#配置community
	cmdgen.UdpTransportTarget(('202.100.1.3',161)),#配置IP地址和端口号
	0,25,#0为non-repeaters 和  25为max-repetitions(一个数据包中最多25个条目，和显示无关)
	'1.3.6.1.2.1.2.2.1.2',#OID
)

"""
non-repeaters介绍
the number of objects that are only expected to return a single GETNEXT instance, not multiple instances. Managers frequently request the value of sysUpTime and only want that instance plus a list of other objects.
max-repetitions介绍
the number of objects that should be returned for all the repeating OIDs. Agent's must truncate the list to something shorter if it won't fit within the max-message size supported by the command generator or the agent.
详细介绍
https://www.webnms.com/snmp/help/snmpapi/snmpv3/snmp_operations/snmp_getbulk.html
"""

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
		print('OID:%s = %s' % (name, val))