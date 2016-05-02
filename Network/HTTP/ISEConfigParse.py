#!/usr/bin/python3.4


# -*- coding=utf-8 -*-


from xml.etree.ElementTree import parse
import pprint

mapping = {}
tree = parse('PolicyConfig.xml')

root = tree.getroot()

rules = root.find('Policies').find('Authentication').find('rules').findall('rule')

mapping = {}

for rule in rules:
	try:
		name = rule.attrib['name']
		result = rule.find('Result')
		resultname = result.attrib['name']
		id_source_rult = rule.find('IdentitySourceRules').find('rule').find('IdentitySourceResult')
		id_source_name = id_source_rult.attrib['name']
		print(('RuleName: ' + '%-25s' + '  Allowed_Proto:' + '%-20s') % (name, resultname))
		print('\nID_Source:' + id_source_name)
		print('-' * 75)
	except:
		pass
