#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from socket import *
#配置本地服务器IP地址
myHost = '202.100.1.138'
#配置本地服务器端口号
myPort = 6666

#创建TCP Socket, AF_INET为IPv4，SOCK_STREAM为TCP
sockobj = socket(AF_INET, SOCK_STREAM)
#绑定套接字到地址，地址为（host，port）的元组
sockobj.bind((myHost, myPort))
#在拒绝连接前，操作系统可以挂起的最大连接数量，一般配置为5
sockobj.listen(5)

while True:#一直接受请求，直到ctl+c终止程序
	#接受TCP连接，并且返回（conn,address）的元组，conn为新的套接字对象，可以用来接收和发送数据，address是连接客户端的地址
    connection, address = sockobj.accept()
    #打印连接客户端的IP地址
    print('Server Connected by', address)
    while True:
        data = connection.recv(1024)#接收数据，1024为bufsize，表示一次接收的最大数据量！
        if not data: break#如果没有数据就退出循环
        connection.send(b'Echo==>' + data)#发送回显数据给客户，注意Python3.x后，发送和接收的数据必须为二进制！
    connection.close()#关闭连接