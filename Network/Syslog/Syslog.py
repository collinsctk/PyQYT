#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import logging
import socketserver
import threading
import re

LOG_FILE = 'pysyslog.log'

logging.basicConfig(level=logging.INFO,
                    format='%(message)s',
                    datefmt='',
                    filename=LOG_FILE,
                    filemode='a')

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        #if re.match('.*changed state to administratively down.*', data):
        #    print( "%s : " % self.client_address[0], str(data))
        #elif re.match('.*changed state to up.*', data):
        #    print( "%s : " % self.client_address[0], str(data))
        print( "%s : " % self.client_address[0], str(data))
        logging.info(str(data))

if __name__ == "__main__":
    try:
        HOST, PORT = "0.0.0.0", 514
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print ("Crtl+C Pressed. Shutting down.")
