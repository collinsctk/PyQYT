#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from get_md5_config import get_md5_config
import pickle
from diff_txt import diff_txt
from PyQYT.Network.SMTP.SMTP_SEND_MAIL_Attachment import qyt_smtp_attachment
from POP3_For_Practice_Lab import qyt_rec_mail
import random
import time

host_list = ['202.100.1.1','202.100.12.2']

def first_bak(host_list, username, password):
	dict_config = get_md5_config(host_list, 'admin', 'cisco')
	#print(dict_config)
	with open('./config_bak/Pickle_Config', "wb") as Pickle_config:
		pickle.dump(dict_config, Pickle_config)
	print('配置备份成功！')

#def first_bak(host_list, username, password):
	#bak_diff_config(host_list, 'admin', 'cisco')
	#with open('./config_bak/Pickle_Config', "rb") as Pickle_config:
	#	test = pickle.load(Pickle_config)
	#	print(test)

def find_diff(host_list, username, password):
	new_md5_dict = get_md5_config(host_list, 'admin', 'cisco', operation=2)
	with open('./config_bak/Pickle_Config', "rb") as Pickle_config:
		old_md5_dict = pickle.load(Pickle_config)
	for x in new_md5_dict:
		if new_md5_dict[x] != old_md5_dict[x][1]:
			diff_md5_dict = get_md5_config(host_list, 'admin', 'cisco')
			diff_result = diff_txt(old_md5_dict[x][0],diff_md5_dict[x][0])
			#print(old_md5_dict[x][0])
			#print('=='*50)
			#print(diff_md5_dict[x][0])
			#print(diff_result )
			return x,diff_result

def check_diff():
	try:
		ip, config_changed = find_diff(host_list, 'admin', 'cisco')
		print('发现配置更改！')
		id_no = str(int(random.random()*10000))
		Subject = ip + ' configuration changed ' + 'reply "y1" for update db ' + id_no
		Main_Body = config_changed
		qyt_smtp_attachment('smtp.163.com',
							'collinsctk',
							'1a.cisco',
							'collinsctk@163.com',
							'collinsctk@qytang.com;collinsctk@163.com',
							Subject,
							Main_Body)
		time.sleep(30)
		operation_code = qyt_rec_mail('pop.163.com', 'collinsctk', '1a.cisco', id_no)
		if operation_code == True:
			print('收到管理员确认！更新数据库！')
			first_bak(host_list, 'admin', 'cisco')

	except TypeError:
		print('配置没有任何修改！')

if __name__ == '__main__':
	#first_bak(host_list, 'admin', 'cisco')
	#find_diff(host_list, 'admin', 'cisco')
	check_diff()