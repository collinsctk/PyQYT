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

def Client_PIC(ip,port,obj):
	msg = pickle.dumps(obj)#把obj pickle到一个二进制字串
	sockobj = socket(AF_INET, SOCK_STREAM)
	sockobj.connect((ip, port))
	send_message = BytesIO(msg)#由于二进制字串无法按照长度读取，所以给他写到一个BytesIO
	send_message_fragment = send_message.read(1024)#读取1024字节长度数据
	while send_message_fragment:	
		sockobj.send(send_message_fragment)#发送数据分片（如果分片的话）
		send_message_fragment = send_message.read(1024)#继续读取数据
	print('Pickle File Sended')
	sockobj.close()

if __name__ == '__main__':
	dict = {'key1':'welcome to qytang', 'key2':[1,2,3,4,5], 'key3':([3,4],'python')}
	Client_PIC('202.100.1.138',6666,dict)