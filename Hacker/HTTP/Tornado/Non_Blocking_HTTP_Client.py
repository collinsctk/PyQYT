#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import tornado.httpclient

def handle_request(response):
    if response.error:
        print("Error:", response.error)
    else:
        print(response.body)


tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
http_client = tornado.httpclient.AsyncHTTPClient()
response = http_client.fetch("http://www.sina.com/")
print(response.result())

#if __name__ == '__main__':
#	#Proxy网址
#	proxy = {'http': '120.198.244.29:8080'}
#	url = 'http://www.qytang.com/'
#	qyt_browser_proxy(url, proxy)
