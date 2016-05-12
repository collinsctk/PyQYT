pools = [{'Network':(202,100,1,0),
  		  'Subnet_Mask':(255,255,255,0),
          'Address_range':(100,200),
          'GateWay':(202,100,1,3),
          'Domain_Name':'qytang.com',
          'Domain Name Servers':(114,114,114,114)}
        ,
         {'Network':(202,100,23,0),
          'Subnet_Mask':(255,255,255,0),
          'Address_range':(100,200),
          'GateWay':(202,100,23,3),
          'Domain_Name':'qytang.com',
          'Domain Name Servers':(114,114,114,114)}
        ]

from PyQYT.Network.Tools.GET_IP_IFCONFIG import get_ip_address_ifconfig
import re

def find_pool_config(GIADDR):
	local_ip = get_ip_address_ifconfig('eno33554944')
	print(GIADDR)
	if GIADDR == '0.0.0.0':
		ip_sections = re.match('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', local_ip['ip_address']).groups()
		for pool in pools:
			if int(ip_sections[0]) == pool['Network'][0] and int(ip_sections[1]) == pool['Network'][1] and int(ip_sections[2]) == pool['Network'][2]:
				print('thos')
				return pool
	else:
		ip_sections = re.match('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', GIADDR).groups()
		for pool in pools:
			if int(ip_sections[0]) == pool['Network'][0] and int(ip_sections[1]) == pool['Network'][1] and int(ip_sections[2]) == pool['Network'][2]:
				return pool