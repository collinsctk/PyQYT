#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from xml.dom.minidom import Document

doc = Document()
root = doc.createElement('root')
doc.appendChild(root)
QYT_Teachers = doc.createElement('亁颐堂老师')
root.appendChild(QYT_Teachers)

Department = doc.createElement('部门')
QYT_Teachers.appendChild(Department)

Security = doc.createElement('安全')
Department.appendChild(Security)

Teachers = doc.createElement('老师')
Security.appendChild(Teachers)

Name1 = doc.createElement('姓名')
Name1.setAttribute('name', '秦柯')

Name2 = doc.createElement('姓名')
Name2.setAttribute('name', '李冰')

Name3 = doc.createElement('姓名')
Name3.setAttribute('name', '刘强龙')

Name4 = doc.createElement('姓名')
Name4.setAttribute('name', '陈家栋')

Teachers.appendChild(Name1)
Teachers.appendChild(Name2)
Teachers.appendChild(Name3)
Teachers.appendChild(Name4)

Courses = doc.createElement('课程')
Security.appendChild(Courses)

Name1 = doc.createElement('课程名')
Name1.setAttribute('name', 'CCNASec')

Name2 = doc.createElement('课程名')
Name2.setAttribute('name', 'ACS5')

Name3 = doc.createElement('课程名')
Name3.setAttribute('name', 'Firewall')

Name4 = doc.createElement('课程名')
Name4.setAttribute('name', 'VPN')

Name5 = doc.createElement('课程名')
Name5.setAttribute('name', 'ISE')

Name6 = doc.createElement('课程名')
Name6.setAttribute('name', 'IPS')

Name7 = doc.createElement('课程名')
Name7.setAttribute('name', 'Secure')

Courses.appendChild(Name1)
Courses.appendChild(Name2)
Courses.appendChild(Name3)
Courses.appendChild(Name4)
Courses.appendChild(Name5)
Courses.appendChild(Name6)
Courses.appendChild(Name7)

Wireless = doc.createElement('无线')
Department.appendChild(Wireless)

Teachers = doc.createElement('老师')
Wireless.appendChild(Teachers)

Name1 = doc.createElement('姓名')
Name1.setAttribute('name', '秦柯')

Name2 = doc.createElement('姓名')
Name2.setAttribute('name', '景鑫')

Teachers.appendChild(Name1)
Teachers.appendChild(Name2)

Courses = doc.createElement('课程')
Wireless.appendChild(Courses)

Name1 = doc.createElement('课程名')
Name1.setAttribute('name', '无线控制器')

Name2 = doc.createElement('课程名')
Name2.setAttribute('name', 'ISE')

Name3 = doc.createElement('课程名')
Name3.setAttribute('name', 'PI_MSE')

Courses.appendChild(Name1)
Courses.appendChild(Name2)
Courses.appendChild(Name3)

DataCenter = doc.createElement('数据中心')
Department.appendChild(DataCenter)

Teachers = doc.createElement('老师')
DataCenter.appendChild(Teachers)

Name1 = doc.createElement('姓名')
Name1.setAttribute('name', '马海波')

Name2 = doc.createElement('姓名')
Name2.setAttribute('name', '唐建东')

Name3 = doc.createElement('姓名')
Name3.setAttribute('name', '秦柯')

Teachers.appendChild(Name1)
Teachers.appendChild(Name2)
Teachers.appendChild(Name3)

Courses = doc.createElement('课程')
DataCenter.appendChild(Courses)

Name1 = doc.createElement('课程名')
Name1.setAttribute('name', 'Nexus交换机')

Name2 = doc.createElement('课程名')
Name2.setAttribute('name', '数据存储')

Name3 = doc.createElement('课程名')
Name3.setAttribute('name', 'UCS')

Courses.appendChild(Name1)
Courses.appendChild(Name2)
Courses.appendChild(Name3)

RS = doc.createElement('路由交换')
Department.appendChild(RS)

Teachers = doc.createElement('老师')
RS.appendChild(Teachers)

Name1 = doc.createElement('姓名')
Name1.setAttribute('name', '周亚军')

Name2 = doc.createElement('姓名')
Name2.setAttribute('name', '李伟达')

Name3 = doc.createElement('姓名')
Name3.setAttribute('name', '徐健坤')

Name4 = doc.createElement('姓名')
Name4.setAttribute('name', '杨学宝')

Name5 = doc.createElement('姓名')
Name5.setAttribute('name', '张雷')

Teachers.appendChild(Name1)
Teachers.appendChild(Name2)
Teachers.appendChild(Name3)
Teachers.appendChild(Name4)
Teachers.appendChild(Name5)

Courses = doc.createElement('课程')
RS.appendChild(Courses)

XML_File = open('./XML_File/QYT.xml','w')
XML_File.write(doc.toprettyxml(indent = '    '))
XML_File.close()