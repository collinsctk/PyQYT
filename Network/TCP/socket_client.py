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

import sys
from socket import *
#连接的服务器地址
serverHost = '202.100.1.138'
#连接的服务器端口号
serverPort = 6666
#发送的回显信息
message = [b'Welcome to QYTANG', b'Welcome to PyQYT']

sockobj = socket(AF_INET, SOCK_STREAM)#创建TCP Socket, AF_INET为IPv4，SOCK_STREAM为TCP
sockobj.connect((serverHost, serverPort))#连接到套接字地址，地址为（host，port）的元组

for line in message:#读取message中的每一行（line）
    sockobj.send(line)#发送读取的每一行信息，注意line已经被encode()为二进制了！
    data = sockobj.recv(1024)#接收数据，1024为bufsize，表示一次接收的最大数据量！
    print('Client Received:', data)#打印接收到的数据

sockobj.close()#关闭连接