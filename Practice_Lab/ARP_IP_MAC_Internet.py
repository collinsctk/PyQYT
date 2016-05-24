#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import re
from PyQYT.Network.ARP.ARP_Scan import arp_scan
#from PyQYT.Network.SSH.Simple_SSH_Client import QYT_SSHClient_SingleCMD
from Simple_Telnet_Return_show import QYT_TelnetClient
def ARP_MAC_IP_Internet(ip, username, password, network_prefix, ifname):
	arp_scan_result = arp_scan(network_prefix, ifname)
	#print(arp_scan_result)
	format_arp_scan_result = []
	for ip,mac in arp_scan_result:
		mac_split_list = mac.split(':')
		new_mac = mac_split_list[0]+mac_split_list[1]+'.'+mac_split_list[2]+mac_split_list[3]+'.'+mac_split_list[4]+mac_split_list[5]
		format_arp_scan_result.append([ip,new_mac])
	arp_scan_result = format_arp_scan_result
	#print(arp_scan_result)
	CAM_result = QYT_TelnetClient(ip, username, password, 'show mac address-table dynamic')
	CAM_result_list = CAM_result.split('\r\n')
	#print(CAM_result_list)
	CAM_Table_list = []
	for line in CAM_result_list:
		if re.match('\s*(\d+)\s+(\w\w\w\w\.\w\w\w\w\.\w\w\w\w)\s+DYNAMIC\s+(\w.*)', line):
			CAM_Table = re.match('\s*(\d+)\s+(\w\w\w\w\.\w\w\w\w\.\w\w\w\w)\s+DYNAMIC\s+(\w.*)', line).groups()
			CAM_Table_list.append(CAM_Table)
	#print(CAM_Table_list)
	for ip,mac in arp_scan_result:
		for vlan, cam_mac, ifname in CAM_Table_list:
			if mac == cam_mac:
				print('IP地址:%-20s MAC地址:%-20s VLAN号:%-5s 接口名:%-10s' % (ip, mac, vlan, ifname))
if __name__ == "__main__":	
	ARP_MAC_IP_Internet('202.100.1.254', 'admin', 'cisco', '202.100.1.0', 'eno33554944')
