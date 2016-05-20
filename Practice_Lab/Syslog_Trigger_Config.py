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

import logging
import socketserver
import threading
import re
from SSH_Client_CMDS import QYT_SSHClient_MultiCMD

LOG_FILE = 'pysyslog.log'

logging.basicConfig(level=logging.INFO,
                    format='%(message)s',
                    datefmt='',
                    filename=LOG_FILE,#log文件
                    filemode='a')#追加模式
F0_CMDS = ['configure terminal', 'interface tunnel 0', 'tunnel source fastEthernet 0/0']
F1_CMDS = ['configure terminal', 'interface tunnel 0', 'tunnel source fastEthernet 1/0']

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())#读取数据
        #============可以配置过滤器仅仅读取接口up/down信息===============
        try:
            if re.match('.*ip sla 1 reachability Up->Down.*', data) and self.client_address[0] == '202.100.1.1':
               QYT_SSHClient_MultiCMD('202.100.1.1', 'admin', 'cisco', F1_CMDS)
               print('mGRE隧道源接口已经切换到Fa1/0')
            elif re.match('.*ip sla 1 reachability Down->Up.*', data) and self.client_address[0] == '202.100.1.1':
               QYT_SSHClient_MultiCMD('202.100.1.1', 'admin', 'cisco', F0_CMDS)
               print('mGRE隧道源接口已经切换回Fa0/0')
        except Exception as e:
            print(e)
        #    print( "%s : " % self.client_address[0], str(data))
        #elif re.match('.*changed state to up.*', data):
        #    print( "%s : " % self.client_address[0], str(data))
        #print( "%s : " % self.client_address[0], str(data))#打印syslog信息
        logging.info(str(data))#把信息logging到本地

if __name__ == "__main__":
    try:
        HOST, PORT = "0.0.0.0", 514#本地地址与端口
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)#绑定本地地址，端口和syslog处理方法
        server.serve_forever(poll_interval=0.5)#运行服务器，和轮询间隔
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:#捕获Ctrl+C，打印信息并退出
        print ("Crtl+C Pressed. Shutting down.")
