#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from xml.dom.minidom import Document
from Source_DB import QYT_Teachers,QYT_Courses#导入字典

#print(QYT_Teachers)#打印字典
#print(QYT_Courses)#打印字典

doc = Document()
root = doc.createElement('root')
doc.appendChild(root)
QYT_Teachers_Element = doc.createElement('亁颐堂老师')
root.appendChild(QYT_Teachers_Element)

Department_Element = doc.createElement('部门')
QYT_Teachers_Element.appendChild(Department_Element)

for Department in QYT_Teachers:
	Sub_Department_Element = doc.createElement(Department)
	Department_Element.appendChild(Sub_Department_Element)
	laoshi = doc.createElement('老师')
	Sub_Department_Element.appendChild(laoshi)
	for Teacher in QYT_Teachers[Department]:
		Teacher_Element = doc.createElement('姓名')
		Teacher_Element.setAttribute('name', Teacher)
		laoshi.appendChild(Teacher_Element)

	kecheng = doc.createElement('课程')
	Sub_Department_Element.appendChild(kecheng)
	try:
		for Course in QYT_Courses[Department]:
			Course_Element = doc.createElement('课程名')
			Course_Element.setAttribute('name', Course)
			kecheng.appendChild(Course_Element)
	except Exception as e:
		pass

XML_File = open('./XML_File/QYT_Auto.xml','w')
XML_File.write(doc.toprettyxml(indent = '    '))
XML_File.close()