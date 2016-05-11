#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import os
import argparse
import socket
import struct
import select
import time

ICMP_ECHO_REQUEST = 8
DEFAULT_TIMEOUT = 2
DEFAULT_COUNT = 4

def do_checksum(source_bin): #计算校验和的方法，传入一个二进制字串（主机字节序）
	#假设需要传入的source_bin = '01100001 01100010 01100011'
	sum = 0
	max_count = (len(source_bin)//2) * 2#其实就是计算当前长度的下一个可以被2（16位）整除的数！如果单出来一个字节（8个位）需要特殊处理！
	# (3//2) * 2 = 2,注意‘//’是整除，因为是16位（两个字节）校验和。 
	count = 0
	while count < max_count:
		val = source_bin[count + 1] * 256 + source_bin[count]
		#source_string[0] = 01100001
		#source_string[1] = 01100010
		#val = source_string[1]*256 + source_string[0]#由于是主机字节序，越往后，越往右位数越高！
		#val = 0110001001100001
		sum = sum + val
		#sum = 0110001001100001
		sum = sum & 0xffffffff #这个操作仅仅只是在扩展位数，从16位扩展到32位
		#sum = 0000000000000000 0110001001100001
		#sum = sum & 0xffffffff
		#0000000000000000 0110001001100001 & 1111111111111111 1111111111111111
		#sum = 0000000000000000 0110001001100001#这个操作仅仅只是在扩展位数，从16位扩展到32位
		count = count + 2 #准备处理下16个位！

	if max_count < len(source_bin):#这个操作是在处理，可能单出来的那个字节！
		sum = sum + source_bin[len(source_bin) - 1]#提取出来最后一个单出来的字节！
		#sum = 0000000000000000 0110001001100001
		#source_string[2] =             01100011
		#sum = 0000000000000000 0110001011000100 #由于只有一个字节，所以就在低位加，如果有两位（当然在这个if里边不可能），第二位在高位加！
		sum = sum & 0xffffffff
		#sum = 0000000000000000 0110001011000100

	sum = (sum >> 16) + (sum & 0xffff) #高位溢出，向低位进位
	#此时sum已经被格式化为16位了，0110001011000100
	#超过16位的高位加到低位，请参考文章‘IP、ICMP、UDP、TCP 校验和算法’，由于我的值未超过16位，所以省略此操作。
	sum = sum + (sum >> 16)#如果再溢出，继续想低位进位
	#超过16位的高位加到低位，请参考文章‘IP、ICMP、UDP、TCP 校验和算法’  由于我的值未超过16位，所以省略此操作。
	#sum = 0110001011000100

	answer = ~sum#校验和为‘16bit字的二进制反码和’，可以先求反后加，但是一般的操作为先加后求反！
	#按位求反，或者说按位翻转。请参考文章‘python中按位翻转是什么意思 公式是～x = -(x+1) 不明白’
	#answer = 0110001011000100求反的结果为1001110100111011
	#answer = 1001110100111011

	answer = answer & 0xffff #再次格式化
	#answer = 1001110100111011
	#	      1111111111111111	
	#answer = 1001110100111011

	#1001110100111011
	#下面是转网络字节序，看具体情况是否需要！
	#answer = answer >> 8 | (answer << 8 & 0xff00) #这里在做高低位互换操作，由主机字节序，转换到网络字节序
	#answer >> 8 = 0000000010011101

	#answer << 8 = 0000000010011101 0011101100000000
	#0xff00                         1111111100000000
	#                               0011101100000000

	#0000000010011101 | 0011101100000000 计算结果如下
	#0011101110011101（说白了就是高位换到低位，低位换到高位，就是主机字节序换到网络字节序）
	return answer

if __name__ == '__main__':
	print(bin(do_checksum(b'abc')))