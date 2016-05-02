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
import time
import struct
import random
import sys
import re

##############################手动制造Fragment################################
#严重注意ICMP的校验和是整ICMP头部和数据部分一起计算的！！！
#frag的数量乘以8，才是真正的偏移量字节数！
send(IP(flags=1,frag=0,id=1,dst='202.100.1.3')/ICMP(chksum=0xab79)/b'welcome to qytang!!!!!!!')
send(IP(flags=1,frag=4,id=1,proto=1,dst='202.100.1.3')/(b'second welcome to qytang!!!!!!!!'))
send(IP(flags=0,frag=8,id=1,proto=1,dst='202.100.1.3')/(b'third welcome to qytang!!!!!!!!'))

##############################自动制造Fragment################################
frags = fragment(IP(dst='202.100.1.3')/ICMP()/(b"qytang"*1000))
#产生每一个分片，可以对分片就行修改！！！！
send(frags)

#正常发包，系统会自动进行分片处理！！！！
send(IP(dst='202.100.1.3')/ICMP()/(b"qytang"*1000))