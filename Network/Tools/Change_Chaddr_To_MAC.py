#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import struct

def Change_Chaddr_To_MAC(chaddr): #转换16字节chaddr为MAC地址，前6字节为MAC，后面暂时无用！！
	MAC_ADDR_INT_List = struct.unpack('>16B', chaddr)[:6]
	MAC_ADDR_List = []
	for MAC_ADDR_INT in MAC_ADDR_INT_List:
		if MAC_ADDR_INT < 16:
			MAC_ADDR_List.append('0' + str(hex(MAC_ADDR_INT))[2:])
		else:
			MAC_ADDR_List.append(str(hex(MAC_ADDR_INT))[2:])
	MAC_ADDR = MAC_ADDR_List[0] + ':' + MAC_ADDR_List[1] + ':' + MAC_ADDR_List[2] + ':' + MAC_ADDR_List[3] + ':' + MAC_ADDR_List[4] + ':' + MAC_ADDR_List[5]
	return MAC_ADDR