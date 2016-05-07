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

import pickle
from io import BytesIO
from socket import *

def Server_PIC(ip,port):
	#创建TCP Socket, AF_INET为IPv4，SOCK_STREAM为TCP
	sockobj = socket(AF_INET, SOCK_STREAM)
	#绑定套接字到地址，地址为（host，port）的元组
	sockobj.bind((ip, port))
	#在拒绝连接前，操作系统可以挂起的最大连接数量，一般配置为5
	sockobj.listen(5)

	while True:#一直接受请求，直到ctl+c终止程序
		#接受TCP连接，并且返回（conn,address）的元组，conn为新的套接字对象，可以用来接收和发送数据，address是连接客户端的地址
		connection, address = sockobj.accept()
		#打印连接客户端的IP地址
		print('Server Connected by', address)		
		recieved_message = b''#预先定义接收信息变量
		recieved_message_fragment = connection.recv(1024)#读取接收到的信息，写入到接收到信息分片
		while recieved_message_fragment:
			recieved_message = recieved_message + recieved_message_fragment#把所有接收到信息分片重组装
			recieved_message_fragment = connection.recv(1024)
		obj = pickle.loads(recieved_message)#把接收到信息pickle回正常的obj
		print(obj)#打印obj，当然也可以选择写入文件或者数据库
		connection.close()

if __name__ == '__main__':
	Server_IP = '0.0.0.0'
	Server_Port = 6666
	Server_PIC(Server_IP,Server_Port)