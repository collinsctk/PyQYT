#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import shelve
from Source_DB import QYT_Teachers,QYT_Courses#导入字典

print(QYT_Teachers)#打印字典
print(QYT_Courses)#打印字典

#创建Shelve数据库文件
Shelve_DB = shelve.open('./Shelve_File/Shelve_DB')

#把Python对象，以Shelve数据库键的方式写入
Shelve_DB['QYT_Teachers'] = QYT_Teachers
Shelve_DB['QYT_Courses'] = QYT_Courses

#关闭并且保存数据库
Shelve_DB.close()

#重新打开Shelve数据库文件
Shelve_DB = shelve.open('./Shelve_File/Shelve_DB')

#读取Shelve数据库键，并还原为Python对象
QYT_Teachers_New = Shelve_DB['QYT_Teachers']
QYT_Courses_New = Shelve_DB['QYT_Courses']

print(QYT_Teachers_New)
print(QYT_Courses_New)
