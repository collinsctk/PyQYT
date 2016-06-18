#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from sshtunnel import SSHTunnelForwarder

server = SSHTunnelForwarder(
    ('202.100.1.139', 22),#Step 2连接远端服务器SSH端口
    ssh_username="root",
    ssh_password="Cisc0123",
    local_bind_address=('192.168.214.200',8080),#Step 1连接本地地址'192.168.214.200',8080
    remote_bind_address=('127.0.0.1', 80)#Step 3跳转到远端服务器'127.0.0.1', 80
)

server.start()

print(server.local_bind_port)#如果不配置local_bind_address,将会随机绑定本地端口，并且打印

#server.stop()
