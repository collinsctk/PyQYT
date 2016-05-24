#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import struct

def int_machex_str(int_no):
	if len(str(hex(int_no))[2:]) == 1:
		str_mac = '0' + str(hex(int_no))[2:]
	else:
		str_mac = str(hex(int_no))[2:]
	return str_mac

def unpack_bootp_header(bin_data):
	sections = struct.unpack('>4BI2H16B6B', bin_data)
	bootp_sections_dict = {}
	bootp_sections_dict['OP'] = sections[0]
	bootp_sections_dict['HTTPE'] = sections[1]
	bootp_sections_dict['HLEN'] = sections[2]
	bootp_sections_dict['HOPS'] = sections[3]
	bootp_sections_dict['XID'] = sections[4]
	bootp_sections_dict['SECS'] = sections[5]
	bootp_sections_dict['FLAGS'] = hex(sections[6])
	bootp_sections_dict['CIADDR'] = '%s.%s.%s.%s' % (sections[7],sections[8],sections[9],sections[10])
	bootp_sections_dict['YIADDR'] = '%s.%s.%s.%s' % (sections[11],sections[12],sections[13],sections[14])
	bootp_sections_dict['SIADDR'] = '%s.%s.%s.%s' % (sections[15],sections[16],sections[17],sections[18])
	bootp_sections_dict['GIADDR'] = '%s.%s.%s.%s' % (sections[19],sections[20],sections[21],sections[22])
	bootp_sections_dict['CHADDR'] = '%s:%s:%s:%s:%s:%s' % (int_machex_str(sections[23]),int_machex_str(sections[24]),int_machex_str(sections[25]),int_machex_str(sections[26]),int_machex_str(sections[27]),int_machex_str(sections[28]))
	return bootp_sections_dict
	#Op：消息操作代码，既可以是引导请求（BOOTREQUEST）也可以是引导答复（BOOTREPLY）
	#Htype：硬件地址类型
	#Hlen：硬件地址长度
	#Xid：处理ID
	#Secs：从获取到IP地址或者续约过程开始到现在所消耗的时间
	#Flags：标记
	#Ciaddr：客户机IP地址
	#Yiaddr：“你的”（客户机）IP地址
	#Siaddr：在bootstrap中使用的下一台服务器的IP地址
	#Giaddr：用于导入的接替代理IP地址
	#Chaddr：客户机硬件
	#Sname：任意服务器主机名称，空终止符
	#File：DHCP发现协议中的引导文件名、空终止符、属名或者空，DHCP供应协议中的受限目录路径名
	#Options：可选参数字段。参考定义选择列表中的选择文件

def unpack_dhcp_header(bin_data):
	dhcp_sections_dict = {}
	dhcp_sections_dict['Magic Cookie'] = hex(struct.unpack('>I',bin_data[:4])[0])
	bin_data = bin_data[4:]
	while True:
		if bin_data[0] == 255:
			break
		else:
			option_code = bin_data[0]
			option_length = bin_data[1]
			if option_code == 53:
				offset = 2 + option_length
				option_data = bin_data[2:offset]
				bin_data = bin_data[offset:]
				Message_DICT = {1:'DHCPDISCOVER',
								2:'DHCPOFFER',
								3:'DHCPREQUEST',
								4:'DHCPDECLINE',
								5:'DHCPACK',
								6:'DHCPNAK',
								7:'DHCPRELEASE',
								8:'DHCPINFORM'}
				dhcp_sections_dict['Message Type'] = Message_DICT[option_data[0]]
				continue
			elif option_code == 12:
				offset = 2 + option_length
				option_data = bin_data[2:offset]
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Host Name'] = option_data.decode()
				continue
			elif option_code == 43:
				offset = 2 + option_length
				option_data = bin_data[2:offset]
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Vendor-Specific Information'] = option_data
				continue
			elif option_code == 55:
				offset = 2 + option_length
				Options_dict = {1:'Subnet Mask',
								3:'Routers',
								6:'Domain Name Servers',
								15:'Domain Name', 
								31:'Perform Router Discovery',
								33:'Static Routes',
								43:'Vendor Specific Information',
								44:'NetBIOS Name Servers',
								46:'NetBIOS Node Type',
								47:'NetBIOS Scope',
								121:'Classless Static Route Option',
								150:'TFTP Server Address'}
				Requested_Options = {}
				for i in range(option_length):
					Option_ID = bin_data[2 + i]
					try:
						Requested_Options[Option_ID] = Options_dict[Option_ID]
					except:
						Requested_Options[Option_ID] = Option_ID
				dhcp_sections_dict['Parameter Request List'] = Requested_Options
				bin_data = bin_data[offset:]
				continue
			elif option_code == 57:
				offset = 2 + option_length
				option_data = struct.unpack('>H',bin_data[2:offset])
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Maximum Message Size'] = option_data[0]
			elif option_code == 60:
				offset = 2 + option_length
				option_data = bin_data[2:offset]
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Vendor Class Indentifier'] = option_data
				continue
			elif option_code == 61:
				offset = 2 + option_length
				Hardware_Type = bin_data[2]
				Hardware_Address = bin_data[3:offset]
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Client Identifier'] = (Hardware_Type,Hardware_Address)
				continue
			elif option_code == 82:
				offset = 2 + option_length
				option_data = bin_data[2:offset]
				bin_data = bin_data[offset:]
				dhcp_sections_dict['Relay Agent Information'] = option_data
				continue
			else:
				offset = 2 + option_length
				bin_data = bin_data[offset:]
				continue
	return dhcp_sections_dict

def DHCP_Unpack_Options(data):
	return [unpack_bootp_header(data[0:34]), unpack_dhcp_header(data[236:])]
