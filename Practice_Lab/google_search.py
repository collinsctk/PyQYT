#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import pprint

from apiclient.discovery import build


def google_search(key_word):

    service = build("customsearch", "v1",
                 developerKey="你的KEY")

    res = service.cse().list(
         q=key_word,
         cx='搜索引擎ID',
         num=10, #Valid values are integers between 1 and 10, inclusive.
    ).execute() 

    for value in res:
        #print(value)
        if 'items' in value:
            for results in res[value]:
            	#print(results)
                print(results['formattedUrl'])

if __name__ == '__main__':
  google_search('现任明教教主')
