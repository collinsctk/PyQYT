#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from socket import *
#连接的服务器地址
myHost = '202.100.1.138'
#连接的服务器端口号
myPort = 6666

#创建TCP Socket, AF_INET为IPv4，SOCK_STREAM为TCP
sockobj = socket(AF_INET, SOCK_STREAM)
#连接到套接字地址，地址为（host，port）的元组
sockobj.connect((myHost,myPort))

while True:#一直执行循环直到break出现！
	msg=input("请输入回显信息(exit退出):")
	if msg != 'exit':
		sockobj.send(msg.encode())
		echo_msg=sockobj.recv(1024)
		print(echo_msg.decode())
	else:
		break
sockobj.close()
print("连接已经结束！！！")

