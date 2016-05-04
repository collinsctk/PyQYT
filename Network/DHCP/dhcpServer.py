# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from scapy.all import *
from PyQYT.Tools.GET_MAC import GET_MAC
from PyQYT.Tools.GET_IP import get_ip_address
from random import randint
import optparse
from time import sleep

class DHCPServer:
	def __init__(self, interface, pool, gateway, dns):
		self.server_mac = GET_MAC(interface)
		self.server_ip = get_ip_address(interface)
		self.subnet_mask = '255.255.255.0'
		self.pool = pool
		self.gateway = gateway
		self.dns = dns
	
	def generateClientIP(self, pool):
		parts = self.pool.split('.')
		clientip = parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + str(randint(1,255))
		self.client_ip = clientip
		return clientip


	#DHCP leases
	def detect_dhcp(self,pkt):
		"""
		#打印出server发送的BOOTP中的option
		if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 2:
			print("\n收到Offer。")
			print(pkt.getlayer(DHCP).fields)
			print(pkt.getlayer(BOOTP).fields)
		if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 5:
			print("\n收到Ack。")
			print(pkt.getlayer(DHCP).fields)
			print(pkt.getlayer(BOOTP).fields)
		"""

		#Send DHCP Offer if DHCP Discovered Detected.
		if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 1:
			print("\n收到Discover。")
			for option in pkt.getlayer(DHCP).options:
				print('option ---> ', option)
			#print(pkt.getlayer(DHCP).fields)
			sendp(
				Ether(src=self.server_mac,dst="ff:ff:ff:ff:ff:ff")/
				IP(src=self.server_ip,dst="255.255.255.255")/
				UDP(sport=67,dport=68)/
				BOOTP(
					op=2, 
					xid=pkt.getlayer(BOOTP).fields['xid'],
					yiaddr=self.generateClientIP(self.pool),
					chaddr=pkt.getlayer(BOOTP).fields['chaddr']+b'\x00'*10,
					options=b'c\x82Sc')/
				DHCP(options=[('message-type', 2), ('subnet_mask', '255.255.255.0'), ('server_id', self.server_ip), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), 'end'])
				)
			print("发送Offer.\n")
		sleep(3)

		#Send DHCP Ack if DHCP Request Detected.
		if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 3:
			print("\n收到Request。")
			sendp(
				Ether(src=self.server_mac,dst="ff:ff:ff:ff:ff:ff")/
				IP(src=self.server_ip,dst="255.255.255.255")/
				UDP(sport=67,dport=68)/
				BOOTP(
					op=2, 
					xid=pkt.getlayer(BOOTP).fields['xid'],
					yiaddr=self.generateClientIP(self.pool),
					chaddr=pkt.getlayer(BOOTP).fields['chaddr']+b'\x00'*10,
					options=b'c\x82Sc')/
				DHCP(options=[('message-type', 5), ('renewal_time', 345600), ('rebinding_time', 604800), ('lease_time', 691200), ('server_id', self.server_ip), ('subnet_mask', '255.255.255.0'), (81, b'\x00\xff\xff'), ('domain', b'cjd.com\x00'), ('router', '192.168.1.254'), 'end', 'pad', 'pad', 'pad', 'pad', 'pad'])
				)
			print("Sending Ack.\n\nCtrl+C退出。\n")
		sleep(3)

	def start(self):
		sniff(prn=self.detect_dhcp,store=0)

def main():
	parser = optparse.OptionParser('python3 dhcpServerScapy.py -i 工作接口 -p 地址池(都是24位) -g 网关 -d DNS服务器')
	parser.add_option('-i', dest = 'interface', type = 'string', help = '指定工作网卡')
	parser.add_option('-p', dest = 'IPPool', type = 'string', help = '指定IP地址池（掩码长度统一为24位）')
	parser.add_option('-g', dest = 'Gateway', type = 'string', help = '指定地址池网关IP')
	parser.add_option('-d', dest = 'DNSServer', type = 'string', help = '指定DNS服务器')

	(options, args) = parser.parse_args()
	intf = options.interface
	ippool = options.IPPool
	gateway = options.Gateway
	dnsserver = options.DNSServer

	if intf == None or ippool == None or gateway == None or dnsserver == None:
		print(parser.usage)
		exit(0)

	server = DHCPServer(intf, ippool,gateway,dnsserver)
	server.start()


if __name__ == '__main__':
	main()
