#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

#配置各种信息，以便调用
localmac = '00:0c:29:8d:5c:b6'
localip = '202.100.1.138'
destip = '202.100.1.139'
ifname = 'eno33554944'

#######################源MAC为本地MAC####目的MAC为广播#########操作码为1（请求）#######################################################由于多个网卡所以需要指派iface###########
result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=destip), iface = ifname, verbose = False)

print('IP地址: ' + result_raw[0].res[0][1][1].fields['psrc'] + ' 所对应的MAC地址为: ' + result_raw[0].res[0][1][1].fields['hwsrc'])