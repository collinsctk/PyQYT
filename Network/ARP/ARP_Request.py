#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

#配置各种信息，以便调用
localmac = '00:0c:29:8d:5c:b6'
localip = '202.100.1.138'
destip = '202.100.1.3'
ifname = 'eno33554944'

#######################源MAC为本地MAC####目的MAC为广播#########操作码为1（请求）#######################################################由于多个网卡所以需要指派iface###########
result_raw = srp(Ether(src=localmac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=localmac, hwdst='00:00:00:00:00:00', psrc=localip, pdst=destip), iface = ifname, timeout = 1, verbose = False)

'''
sr() function is for sending packets and receiving answers. The function #returns a couple of packet and answers, and the unanswered packets. 
sr1() is a variant that only return one packet that answered the packet (or #the packet set) sent. The packets must be layer 3 packets (IP, ARP, etc.). 
srp() do the same for layer 2 packets (Ethernet, 802.3, etc.).
send() function will send packets at layer 3. That is to say it will handle routing and layer 2 for you. 
sendp() function will work at layer 2.
'''

#print(result_raw[0].res[0][1].getlayer(ARP).fields)
#print(result_raw[0].res[0][1].getlayer(ARP).fields['hwsrc'])
#(<Results: TCP:0 UDP:0 ICMP:0 Other:1>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)
#print(result_raw[0])
#<Results: TCP:0 UDP:0 ICMP:0 Other:1>
#print(type(result_raw[0]))
#<class 'scapy.plist.SndRcvList'>
#res是<class 'scapy.plist.SndRcvList'>的方法，产生收发数据的清单
#https://fossies.org/dox/scapy-2.3.1/classscapy_1_1plist_1_1SndRcvList.html
#print(result_raw[0].res)
#这是一个清单，清单内的item为元组，元组由发送数据包，和一个或者多个接收数据包组成
#[(<Ether  dst=FF:FF:FF:FF:FF:FF src=00:0c:29:8d:5c:b6 type=ARP |<ARP  op=who-has hwsrc=00:0c:29:8d:5c:b6 psrc=202.100.1.138 hwdst=00:00:00:00:00:00 pdst=202.100.1.139 |>>, <Ether  dst=00:0c:29:8d:5c:b6 src=00:0c:29:43:52:cf type=ARP |<ARP  hwtype=0x1 ptype=IPv4 hwlen=6 plen=4 op=is-at hwsrc=00:0c:29:43:52:cf psrc=202.100.1.139 hwdst=00:0c:29:8d:5c:b6 pdst=202.100.1.138 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>)]
#print(result_raw[0].res[0])
#提取[0]，第一个元组（收发数据），元组内包含发送数据包，和一个或者多个接收数据包
#(<Ether  dst=FF:FF:FF:FF:FF:FF src=00:0c:29:8d:5c:b6 type=ARP |<ARP  op=who-has hwsrc=00:0c:29:8d:5c:b6 psrc=202.100.1.138 hwdst=00:00:00:00:00:00 pdst=202.100.1.139 |>>, <Ether  dst=00:0c:29:8d:5c:b6 src=00:0c:29:43:52:cf type=ARP |<ARP  hwtype=0x1 ptype=IPv4 hwlen=6 plen=4 op=is-at hwsrc=00:0c:29:43:52:cf psrc=202.100.1.139 hwdst=00:0c:29:8d:5c:b6 pdst=202.100.1.138 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>)
#print(type(result_raw[0].res[0][0]))
#类型为<class 'scapy.layers.l2.Ether'>
#具体处理方法请查看如下网址
#https://fossies.org/dox/scapy-2.3.1/classscapy_1_1layers_1_1l2_1_1Ether.html
#print(result_raw[0].res[0][0].mysummary())
#00:0c:29:8d:5c:b6 > FF:FF:FF:FF:FF:FF (ARP)
#print(result_raw[0].res[0][0].show())
"""
###[ Ethernet ]###
  dst       = FF:FF:FF:FF:FF:FF
  src       = 00:0c:29:8d:5c:b6
  type      = ARP
###[ ARP ]###
     hwtype    = 0x1
     ptype     = IPv4
     hwlen     = 6
     plen      = 4
     op        = who-has
     hwsrc     = 00:0c:29:8d:5c:b6
     psrc      = 202.100.1.138
     hwdst     = 00:00:00:00:00:00
     pdst      = 202.100.1.139
"""
#print(result_raw[0].res[0][1].mysummary())
#00:0c:29:43:52:cf > 00:0c:29:8d:5c:b6 (ARP)
#print(result_raw[0].res[0][1].show())
"""
###[ Ethernet ]###
  dst       = 00:0c:29:8d:5c:b6
  src       = 00:0c:29:43:52:cf
  type      = ARP
###[ ARP ]###
     hwtype    = 0x1
     ptype     = IPv4
     hwlen     = 6
     plen      = 4
     op        = is-at
     hwsrc     = 00:0c:29:43:52:cf
     psrc      = 202.100.1.139
     hwdst     = 00:0c:29:8d:5c:b6
     pdst      = 202.100.1.138
###[ Padding ]###
        load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
"""
#print(result_raw[0].res[0][1][0].fields)
#产生以太网头部字段名字与值得字典
#{'dst': '00:0c:29:8d:5c:b6', 'type': 2054, 'src': '00:0c:29:43:52:cf'}
#print(result_raw[0].res[0][1][1].fields)
#产生以ARP头部字段名字与值得字典
#{'hwsrc': '00:0c:29:43:52:cf', 'op': 2, 'hwlen': 6, 'plen': 4, 'hwtype': 1, 'ptype': 2048, 'pdst': '202.100.1.138', 'hwdst': '00:0c:29:8d:5c:b6', 'psrc': '202.100.1.139'}

#(<Results: TCP:0 UDP:0 ICMP:0 Other:1>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>) 一个元组，[0]收到响应的数据包，[1]未收到响应的数据包
#print(type(result_raw[0]))
#<class 'scapy.plist.SndRcvList'> #https://fossies.org/dox/scapy-2.3.1/classscapy_1_1plist_1_1SndRcvList.html

result_list = result_raw[0].res #res: the list of packets，产生由收发数据包所组成的清单（list）

#print(result_list)
#[(<Ether  dst=FF:FF:FF:FF:FF:FF src=00:0c:29:8d:5c:b6 type=ARP |<ARP  op=who-has hwsrc=00:0c:29:8d:5c:b6 psrc=202.100.1.138 hwdst=00:00:00:00:00:00 pdst=202.100.1.139 |>>, <Ether  dst=00:0c:29:8d:5c:b6 src=00:0c:29:43:52:cf type=ARP |<ARP  hwtype=0x1 ptype=IPv4 hwlen=6 plen=4 op=is-at hwsrc=00:0c:29:43:52:cf psrc=202.100.1.139 hwdst=00:0c:29:8d:5c:b6 pdst=202.100.1.138 |<Padding load=‘\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00’ |>>>)]
#一个列表，每一个item为一个元组，元组内包括一次ARP请求与回应

#result_list[0][1][0]，[0]表示第一组数据包（收发），[1]，表示收包（0为发包），[0]表示以太网头部
#print(result_list[0][1][0].fields) 以太网头部字段
#{'dst': '00:0c:29:8d:5c:b6', 'type': 2054, 'src': '00:0c:29:43:52:cf'}

#result_list[0][1][0]，[0]表示第一组数据包（收发），[1]，表示收包（0为发包），[1]表示ARP头部
#print(result_list[0][1][1].fields) ARP头部字段
#{'pdst': '202.100.1.138', 'hwtype': 1, 'hwdst': '00:0c:29:8d:5c:b6', 'plen': 4, 'ptype': 2048, 'hwsrc': '00:0c:29:43:52:cf', 'op': 2, 'hwlen': 6, 'psrc': '202.100.1.139'}

print('IP地址: ' + result_list[0][1][1].fields['psrc'] + ' MAC地址: ' + result_list[0][1][1].fields['hwsrc'])
#print('IP地址: ' + result_list[0][1].getlayer(ARP).fields['psrc'] + ' MAC地址: ' + result_list[0][1].getlayer(ARP).fields['hwsrc'])