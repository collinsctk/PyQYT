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

import paramiko
import re
import random
import time

from PyQYT.Network.SMTP.SMTP_SEND_MAIL_Attachment import qyt_smtp_attachment
from POP3_For_Practice_Lab import qyt_rec_mail
from SSH_Client_CMDS import QYT_SSHClient_MultiCMD

white_list = ['202.100.1.101', '202.100.1.1']

def QYT_SSHClient_SingleCMD(ip, username, password, cmd):
	try:
		ssh = paramiko.SSHClient()#创建SSH Client
		ssh.load_system_host_keys()#加载系统SSH密钥
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())#添加新的SSH密钥
		ssh.connect(ip,port=22,username=username,password=password,timeout=5,compress=True)#SSH连接
		stdin,stdout,stderr = ssh.exec_command(cmd)#执行命令
		x = stdout.read().decode()#读取回显
		return x
		ssh.close()
	except Exception as e:
		print('%stErrorn %s'%(ip, e))

def get_top_talkers(ip, username, password):
	SSH_Result = QYT_SSHClient_SingleCMD(ip, username, password, 'show ip flow top-talkers')
	SSH_Result_List_Raw = SSH_Result.split('\r\n')
	SSH_Result_List = []
	for line in SSH_Result_List_Raw:
		if line == '':
			continue
		if re.match('.*top talkers.*', line):
			continue
		if re.match('.*SrcIPaddress.*', line):
			continue
		else:
			tmp = re.search('(\w.*)\s+(\w.*)\s+(\w.*)\s+(\w.*)\s+(\w.*)\s+(\w.*)\s+(\w.*)\s+(\w.*)', line).groups()
			tmp_list = [z.strip() for z in tmp]
			SSH_Result_List.append(tmp_list)
	return SSH_Result_List

def top_talkers_smtp_alert(ip, username, password):
	local_ip = ip
	local_username = username
	local_password = password

	top_talkers_not_in_white_list = []
	for i in get_top_talkers(ip, username, password)[:3]:
		found = 0
		for x in white_list:			
			if i[1] == x:
				found = 1
			else:
				continue
		if found == 0:
			top_talkers_not_in_white_list.append(i[1])

		new_list = []#清除重复IP地址
		for i in top_talkers_not_in_white_list:#清除重复IP地址
			if not i in new_list:
				new_list.append(i)
		top_talkers_not_in_white_list = new_list

	if top_talkers_not_in_white_list != []:
		id_no = str(int(random.random()*10000))
		Subject = 'Top Talker not in the white list ' + id_no
		Main_Body = 'Top Talker host not in the white list\n'
		for ip in top_talkers_not_in_white_list:
			Main_Body = Main_Body + ip + '\n'
		Main_Body = Main_Body + 'Pls reply in 1 min, y1 (for kill), n2 (do noting)[default]'
		qyt_smtp_attachment('smtp.163.com',
							'collinsctk',
							'1a.cisco',
							'collinsctk@163.com',
							'collinsctk@qytang.com;collinsctk@163.com',
							Subject,
							Main_Body)
		time.sleep(30)
		operation_code = qyt_rec_mail('pop.163.com', 'collinsctk', '1a.cisco', id_no)
		#print(operation_code)

		if operation_code == True:
			cmds = ['configure terminal', 'ip access-list extended python_acl_'+id_no]
			for ip in top_talkers_not_in_white_list:
				cmd = 'deny ip host ' + ip + ' any'
				cmds.append(cmd)
			cmd = 'permit ip any any'
			cmds.append(cmd)
			cmd = 'interface FastEthernet2/0'
			cmds.append(cmd)
			cmd = 'ip access-group python_acl_' + id_no + ' in'
			cmds.append(cmd)

			QYT_SSHClient_MultiCMD(local_ip, local_username, local_password, cmds)

		time.sleep(20)
		del_cmds = ['configure terminal']
		cmd = 'no ip access-list extended python_acl_'+id_no
		del_cmds.append(cmd)
		cmd = 'interface FastEthernet2/0'
		del_cmds.append(cmd)
		cmd = 'no ip access-group python_acl_' + id_no + ' in'
		del_cmds.append(cmd)
		QYT_SSHClient_MultiCMD(local_ip, local_username, local_password, del_cmds)


if __name__ == '__main__':
	top_talkers_smtp_alert('202.100.1.1', 'admin', 'cisco')