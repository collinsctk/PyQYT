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

import urllib.request
from bs4 import BeautifulSoup

def Parser_HTTP_Items(url, type):
	print('发现在URL:'+ url + '上' + type + '类型的文件！')
	urlContent = urllib.request.urlopen(url).read()#读取对URL请求的回应
	soup = BeautifulSoup(urlContent, "html.parser")#对HTTP进行分析
	itemTags = soup.find_all(type)#提取特定类型文件的清单
	item_urls = []#最终返回的，特定文件的URL清单
	for img in itemTags:#遍历整个文件清单
		try:
			item_url = url + img['src']#提取文件的URI位置，并且加上URL前缀，组成一个完整的URL
			item_urls.append(item_url)#把完整的URL加入清单
		except:
			pass
	return item_urls#返回特定文件的URL清单
if __name__ == '__main__':
	#print(Parser_HTTP_Items('http://www.qytang.com', 'img'))
	print(Parser_HTTP_Items('http://www.qytang.com', 'script'))
