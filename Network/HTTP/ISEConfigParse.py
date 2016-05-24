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

from xml.etree.ElementTree import parse

tree = parse('PolicyConfig.xml')#打开分析的XML文件

root = tree.getroot()#找到根位置

rule_list = root.find('Policies').find('Authentication').find('rules').findall('rule')

"""
XML实例:
<?xml version="1.0" encoding="UTF-8"?><Root>
  <!--This section describes the policies configured in ISE-->
  <Policies>#####首先找到'Policies'！！！
    <Authentication>#####然后往下找到'Authentication'！！！
      <rules>#####再往下找到'rules'！！！
        <rule name="CCNPSecurity"+++++提取rule的属性'name'+++++ status="Enabled">#####然后'findall'(找到所有)的'rule',返回一个rule_list清单
          <Conditions relationship="AND">
            <Condition type="ADHOC">DEVICE:Location EQUALS Location#All Locations#Beijing</Condition>
            <Condition type="ADHOC">DEVICE:Device Type EQUALS Device Type#All Device Types#Router</Condition>
            <Condition type="ADHOC">DEVICE:Department EQUALS Department#ALL Department#Security#CCNPSecurity</Condition>
            <Condition type="ADHOC">Radius:NAS-Port-Type EQUALS Virtual</Condition>
          </Conditions>
          <Result name="PAP" +++++提取Result的属性'name'+++++type="AllowedProtocolServices"/>
          <IdentitySourceRules>~~~~~在rule下找到'IdentitySourceRules'~~~~~
            <rule name="Default" status="Enabled">~~~~~继续查找'rule'~~~~~
              <Conditions/>
              <IdentitySourceResult name="QYTANG">~~~~~再继续找到'IdentitySourceResult'~~~~~
                <IdentitySource name="QYTANG" type="IdentityStore"/>
                <AuthenFailed>REJECT</AuthenFailed>
                <UserNotFound>REJECT</UserNotFound>
                <ProcessFailed>DROP</ProcessFailed>
              </IdentitySourceResult>
            </rule>
          </IdentitySourceRules>
        </rule>
"""

for rule in rule_list:#遍历所有的rule
	try:
		name = rule.attrib['name']#提取rule的属性'name'
		result = rule.find('Result')#在rule下找到'Result'
		resultname = result.attrib['name']#提取Result的属性'name'
		IdentitySourceResult = rule.find('IdentitySourceRules').find('rule').find('IdentitySourceResult')
		#在rule下找到'IdentitySourceRules',继续查找'rule',再继续找到'IdentitySourceResult'
		id_source_name = IdentitySourceResult.attrib['name']#提取'IdentitySourceResult'的属性'name'
		print(('RuleName: ' + '%-25s' + '  Allowed_Proto:' + '%-20s') % (name, resultname))#打印认证规则的名字和允许的协议
		print('\nID_Source:' + id_source_name)#打印使用的身份数据库
		print('-' * 75)
	except:
		pass
