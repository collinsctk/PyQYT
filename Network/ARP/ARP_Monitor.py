#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from ARP_Table import ARP_Table #导入合法的IP-ARP映射关系字典
from scapy.all import *

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #找到ARP数据包中操作码为1（who-has）或者2（is-at）的数据包
        if ARP_Table.get(pkt[ARP].psrc):#如果ARP的psrc（IP地址）字段在合法的IP-ARP映射关系字典中存在
        	if ARP_Table[pkt[ARP].psrc] == pkt[ARP].hwsrc:#映射的MAC地址与合法的IP-ARP映射关系字典中MAC地址相符
        		print("IP地址: " + pkt[ARP].psrc + " MAC地址: " + pkt[ARP].hwsrc + " 匹配")
        	else:#映射的MAC地址与合法的IP-ARP映射关系字典中MAC地址不相符
        		print("IP地址: " + pkt[ARP].psrc + " MAC地址: " + pkt[ARP].hwsrc + " 不匹配！！！")
        else:#如果ARP的psrc（IP地址）字段在合法的IP-ARP映射关系字典中不存在
        	print("IP地址: " + pkt[ARP].psrc + " MAC地址: " + pkt[ARP].hwsrc + " 未找到条码！！！")
#捕获数据包###通过方法arp_monitor_callback进行处理，filer过滤arp数据包，store=0不保存数据，iface指派接口
sniff(prn=arp_monitor_callback, filter="arp", store=0, iface='eno33554944')