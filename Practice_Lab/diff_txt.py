#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from difflib import *

def diff_txt(file1,file2):
	txt1 = open(file1, 'r').readlines()
	txt2 = open(file2, 'r').readlines()
	result = Differ().compare(txt1, txt2)
	return_result = '\n'.join(list(result))
	return return_result

def diff_txt(txt1,txt2):
	txt1_list = txt1.decode().split('\r\n')
	txt2_list = txt2.decode().split('\r\n')
	result = Differ().compare(txt1_list, txt2_list)
	return_result = '\r\n'.join(list(result))
	return return_result

if __name__ == '__main__':
	txt1 = b"\r\nBuilding configuration...\r\n\r\nCurrent configuration : 2406 bytes\r\n!\r\nversion 15.2\r\nservice timestamps debug datetime msec\r\nservice timestamps log datetime msec\r\n!\r\nhostname R1\r\n!\r\nboot-start-marker\r\nboot-end-marker\r\n!\r\n!\r\n!\r\nno aaa new-model\r\n!\r\n!\r\n!\r\n!\r\n!\r\n!\r"
	txt2 = b"\r\nBuilding configur...\r\n\r\nCurrent configuran : 2407 bytes\r\n!\r\nversion 15.2\r\nservice timestamps debug datetime msec\r\nservice timestamps log datetime msec\r\n!\r\nhostname R1\r\n!\r\nboot-start-marker\r\nboot-end-marker\r\n!\r\n!\r\n!\r\nno aaa new-model\r\n!\r\n!\r\n!\r\n!\r\n!\r\n!\r"
	print(diff_txt(txt1,txt2))

