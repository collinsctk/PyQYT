#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from xml.etree.ElementTree import parse

tree = parse('./XML_File/QYT_Auto.xml')#打开分析的XML文件

root = tree.getroot()#找到根位置

Security_Teachers = root.find('亁颐堂老师').find('部门').find('安全').find('老师').findall('姓名')

for Teacher in Security_Teachers:
	print(Teacher.attrib['name'])