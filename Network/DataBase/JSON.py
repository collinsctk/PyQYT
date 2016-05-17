#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import json
from Source_DB import QYT_Teachers,QYT_Courses#导入字典

print(QYT_Teachers)#打印字典
print(QYT_Courses)#打印字典

#把Python对象转换为JSON格式，并且写入文件
with open('./JSON_File/QYT_Teachers.json', 'w') as f:
    json.dump(QYT_Teachers, f)

with open('./JSON_File/QYT_Courses.json', 'w') as f:
    json.dump(QYT_Courses, f)

#读取JSON文件，并且转换为Python对象
with open('./JSON_File/QYT_Teachers.json', 'r') as f:
    QYT_Teachers_New = json.load(f)

with open('./JSON_File/QYT_Courses.json', 'r') as f:
    QYT_Courses_New = json.load(f)

#打印Python对象
print(QYT_Teachers_New)
print(QYT_Courses_New)
