#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import tornado.ioloop
import tornado.web
import tornado.netutil
import tornado.process
import tornado.httpserver
import tornado.ioloop

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
	app = make_app()
	sockets = tornado.netutil.bind_sockets(8888)
	tornado.process.fork_processes(0)
	server = tornado.httpserver.HTTPServer(app)
	server.add_sockets(sockets)
	tornado.ioloop.IOLoop.current().start()