#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import urllib.request
from bs4 import BeautifulSoup

def Parser_HTTP_Items(url, type):
	print('发现在URL上',type,'类型文件: ' + url)
	urlContent = urllib.request.urlopen(url).read()
	soup = BeautifulSoup(urlContent, "html.parser")
	itemTags = soup.find_all(type)
	item_urls = []
	for img in itemTags:
		try:
			item_url = url + img['src']
			item_urls.append(item_url)
		except:
			pass
	return item_urls
if __name__ == '__main__':
	print(Parser_HTTP_Items('http://www.qytang.com', 'img'))
	#print(Parser_HTTP_Items('http://www.qytang.com', 'script'))
