#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import os
import re#导入正则表达式模块
def get_mac_address(iface):#定义获取MAC地址的模块，传入接口名字
    #data = commands.getoutput("ifconfig " + iface)
    data = os.popen("ifconfig " + iface).read()#运行linux系统命令‘ifconifg’，并且读取输出信息赋值到data
    words = data.split()#把data中的数据通过空格分隔，并且产生清单
    found = 0#是否找到MAC地址
    location = 0#搜索清单的位置记录
    index = 0#MAC地址所在清单中的位置
    for x in words:#遍历整个清单
        if re.match('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', x):#匹配MAC地址字段
            found = 1#MAC地址被找到
            index = location#记录MAC地址出现的位置
            break#跳出循环
        else:#如果没有匹配MAC地址字段
            location = location + 1#继续执行循环，收索下一个位置，所以location需要加1
    if found == 1:#如果MAC地址被找到
        mac = words[index]#提取清单中MAC地址（通过记录的位置），并且赋值到mac
    else:#如果没有找到MAC地址
        mac = 'Mac not found'#返回MAC地址没找到的信息
    return mac#返回mac

if __name__ == "__main__":
    print(get_mac_address('eno33554944'))

