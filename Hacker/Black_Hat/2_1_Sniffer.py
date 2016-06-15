#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import socket
import os

host = "202.100.1.138"

if os.name == 'nt':
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host,0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print(sniffer.recvfrom(65535))

if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)	

