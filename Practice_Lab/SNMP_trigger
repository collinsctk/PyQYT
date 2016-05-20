#!/usr/bin/python3
# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import mygetnext
from mygetnext import snmpv3_getnext as snmpv3_getnext
import time
from SSH_Netflow_TopTalker import top_talkers_smtp_alert
import multiprocessing

#打印接口带宽利用率，并且返回字符串
def bandUtil():
	#获取初始值
	snmpv3_getnext('202.100.1.1', 'qytanguser', 'sha', 'Cisc0123', 'des', 'Cisc0123', '1.3.6.1.2.1.2.2.1.5.0', 3)
	ifSpeedlist = mygetnext.vallist
	snmpv3_getnext('202.100.1.1', 'qytanguser', 'sha', 'Cisc0123', 'des', 'Cisc0123', '1.3.6.1.2.1.2.2.1.10.0', 3)
	inOctetslist1 = mygetnext.vallist
	snmpv3_getnext('202.100.1.1', 'qytanguser', 'sha', 'Cisc0123', 'des', 'Cisc0123', '1.3.6.1.2.1.2.2.1.16.0', 3)
	outOctetslist1 = mygetnext.vallist

	time.sleep(5)
	time1 = time.time()
	#5s后获取当时的值

	while True:
		try:
			snmpv3_getnext('202.100.1.1', 'qytanguser', 'sha', 'Cisc0123', 'des', 'Cisc0123', '1.3.6.1.2.1.2.2.1.10.0', 3)
			inOctetslist2 = mygetnext.vallist
			snmpv3_getnext('202.100.1.1', 'qytanguser', 'sha', 'Cisc0123', 'des', 'Cisc0123', '1.3.6.1.2.1.2.2.1.16.0', 3)
			outOctetslist2 = mygetnext.vallist

			result00, result10, result11 = 0, 0, 0
			f00speed, f10speed, f11speed = int(ifSpeedlist[0]), int(ifSpeedlist[1]), int(ifSpeedlist[2])
			f00changein, f10changein, f11changein = int(inOctetslist2[0])-int(inOctetslist1[0]), int(inOctetslist2[1])-int(inOctetslist1[1]), int(inOctetslist2[2])-int(inOctetslist1[2])
			f00changeout, f10changeout, f11changeout = int(outOctetslist2[0])-int(outOctetslist2[0]), int(outOctetslist2[1])-int(outOctetslist2[1]), int(outOctetslist2[2])-int(outOctetslist2[2])
			in_out00, in_out10, in_out11 = f00changein - f00changeout, f10changein - f10changeout, f11changein - f11changeout

			if in_out00 > 0:
				result00 = f00changein
			else:
				result00 = f00changeout

			if in_out10 > 0:
				result10 = f10changein
			else:
				result10 = f10changeout

			if in_out11 > 0:
				result11 = f11changein
			else:
				result11 = f11changeout

			util00, util10, util11 = float((result00*8*100))/(5*f00speed), float((result10*8*100))/(5*f10speed), float((result11*8*100))/(5*f11speed)
			print('Fa0/0 接口带宽利用率为 %.6f %s' % (util00, '%'))
			print('Fa1/0 接口带宽利用率为 %.6f %s' % (util10, '%'))
			print('Fa2/0 接口带宽利用率为 %.6f %s' % (util11, '%'))
			time2 = time.time()
			time_to_pass = time2-time1
			#print(type(time_to_pass))
			print('冷却时间(120s): %.2f 秒' % time_to_pass)
			if time2 - time1 > 120:
				if util11 > 1:
					time1 = time.time()
					print('Trigger Action')
					multi_dos = multiprocessing.Process(target=top_talkers_smtp_alert, args=('202.100.1.1', 'admin', 'cisco'))
					multi_dos.start()
			print()

			inOctetslist1 = inOctetslist2
			outOctetslist1 = outOctetslist2
			time.sleep(5)
		except Exception as e:
			print(e)

if __name__ == '__main__':
	print('监控Fa0/0, Fa1/0, Fa2/0接口带宽利用率. 轮询周期为5秒')
	bandUtil()
