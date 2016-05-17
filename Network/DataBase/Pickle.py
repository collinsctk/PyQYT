#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import pickle
from Source_DB import QYT_Teachers,QYT_Courses#导入字典

print(QYT_Teachers)#打印字典
print(QYT_Courses)#打印字典

#把Python对象Pickle到文件
Pickle_QYT_Teachers = open('./Pickle_File/Pickle_QYT_Teachers','wb')
pickle.dump(QYT_Teachers, Pickle_QYT_Teachers)
Pickle_QYT_Courses = open('./Pickle_File/Pickle_QYT_Courses','wb')
pickle.dump(QYT_Courses, Pickle_QYT_Courses)

#读取Pickle文件,并转换为Python对象
Pickle_QYT_Teachers = open('./Pickle_File/Pickle_QYT_Teachers','rb')
QYT_Teachers_New = pickle.load(Pickle_QYT_Teachers)
Pickle_QYT_Courses = open('./Pickle_File/Pickle_QYT_Courses','rb')
QYT_Courses_New = pickle.load(Pickle_QYT_Courses)

print(QYT_Teachers_New)
print(QYT_Courses_New)

