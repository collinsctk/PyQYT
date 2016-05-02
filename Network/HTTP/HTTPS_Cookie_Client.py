#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

import http.cookiejar
import urllib
import urllib.request
import urllib.error

def extract_cookie_info(LOGIN_URL, NORMAL_URL, User_Format, Pass_Format, USERNAME, PASSWORD):
    qyt_cookie = http.cookiejar.CookieJar()
    login_data = (urllib.parse.urlencode({User_Format : USERNAME, Pass_Format : PASSWORD})).encode()

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(qyt_cookie))
    resp = opener.open(LOGIN_URL, login_data)

    for cookie in qyt_cookie:
        print("----First time cookie: %s ---> %s" %(cookie.name, cookie.value))

    print("Headers : %s" %resp.headers)
    print("Headers : %s" %resp.status)
    print("Headers : %s" %resp.reason)

    resp = opener.open(NORMAL_URL)
    for cookie in qyt_cookie:
        print("----Second time cookie: %s ---> %s" %(cookie.name, cookie.value))

    print("Headers : %s" %resp.headers)
    print("Headers : %s" %resp.status)
    print("Headers : %s" %resp.reason)

if __name__ == "__main__":
	#User_Format = 'loginname'
	#Pass_Format = 'nloginpwd'
	#USERNAME = 'collinsctk'
	#PASSWORD = 'XXXXX'
	#LOGIN_URL = 'https://passport.jd.com/uc/login?ltype=login'
	#NORMAL_URL = 'http://www.jd.com'
	User_Format = 'TPL_username'
	Pass_Format = 'TPL_password'
	USERNAME = 'cq_bomb'
	PASSWORD = 'XXXXX'
	LOGIN_URL = 'https://login.taobao.com/'
	NORMAL_URL = 'https://www.taobao.com'

	extract_cookie_info(LOGIN_URL, NORMAL_URL, User_Format, Pass_Format, USERNAME, PASSWORD)
