#!/usr/bin/python3
# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.entity.rfc3413.oneliner import cmdgen
import sys
from io import StringIO

vallist = []
cmdGen = cmdgen.CommandGenerator()

def snmpv3_getnext(ip='',user='',hash_meth=None,hash_key=None,cry_meth=None,cry_key=None,oid='',num=1):
	#usmHMACMD5AuthProtocol - MD5 hashing
    #usmHMACSHAAuthProtocol - SHA hashing
    #usmNoAuthProtocol - no authentication
    #usmDESPrivProtocol - DES encryption
    #usm3DESEDEPrivProtocol - triple-DES encryption
    #usmAesCfb128Protocol - AES encryption, 128-bit
    #usmAesCfb192Protocol - AES encryption, 192-bit
    #usmAesCfb256Protocol - AES encryption, 256-bit
    #usmNoPrivProtocol - no encryption
    hashval = None
    cryval = None

    global vallist
    vallist = [None]*num
    #NoAuthNoPriv
    if hash_meth == None and cry_meth == None:
        hashval = cmdgen.usmNoAuthProtocol
        cryval = cmdgen.usmNoPrivProtocol
    #AuthNoPriv
    elif hash_meth != None and cry_meth == None:
    	if hash_meth == 'md5':
    		hashval = cmdgen.usmHMACMD5AuthProtocol
    	elif hash_meth == 'sha':
    		hashval = cmdgen.usmHMACSHAAuthProtocol
    	else:
    		print('哈希算法必须是md5 or sha!')
    		return
    	cryval = cmdgen.usmNoPrivProtocol
    #AuthPriv
    elif hash_meth != None and cry_meth != None:
    	if hash_meth == 'md5':
    		hashval = cmdgen.usmHMACMD5AuthProtocol
    	elif hash_meth == 'sha':
    		hashval = cmdgen.usmHMACSHAAuthProtocol
    	else:
    		print('哈希算法必须是md5 or sha!')
    		return
    	if cry_meth == '3des':
    		cryval = cmdgen.usm3DESEDEPrivProtocol
    	elif cry_meth == 'des':
    		cryval = cmdgen.usmDESPrivProtocol
    	elif cry_meth == 'aes128':
    		cryval = cmdgen.usmAesCfb128Protocol
    	elif cry_meth == 'aes192':
    		cryval = cmdgen.usmAesCfb192Protocol
    	elif cry_meth == 'aes256':
    		cryval = cmdgen.usmAesCfb256Protocol
    	else:
    		print('加密算法必须是3des, des, aes128, aes192 or aes256 !')
    		return
    #提供的参数不符合标准时给出提示
    else:
    	print('三种USM: NoAuthNoPriv, AuthNoPriv, AuthPriv.。请选择其中一种。')
    	return

    errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
        cmdgen.UsmUserData(user, hash_key, cry_key,
                           authProtocol=hashval,
                           privProtocol=cryval),
        cmdgen.UdpTransportTarget((ip, 161)),
        oid,
        lexicographicMode=True, maxRows=num, ignoreMonIncreasingOid=True
    )

    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
                )
            )
        else:
            oid_list = []
            for varBindTableRow in varBindTable:
                for oid, val in varBindTableRow:
                    o = StringIO()
                    print(oid,file=o)
                    oid_get = o.getvalue().strip()
                    o.close()
                    v = StringIO()
                    print(val,file=v)
                    val_get = v.getvalue().strip()
                    v.close()
                    oid_list.append((oid_get,val_get))

    return(oid_list)

if __name__ == '__main__':
    try:
        ip = sys.argv[1]
        user = sys.argv[2]
        hm = sys.argv[3]
        hk = sys.argv[4]
        cm = sys.argv[5]
        ck = sys.argv[6]
        oid = sys.argv[7]
        num = int(sys.argv[8])
        for item in snmpv3_getnext(ip,user,hm,hk,cm,ck,oid,num):
            print('OID: ', item[0], 'VALUE: ', item[1])

    except Exception as e:
        #print(e)
        print('参数设置应该如下:')
        print('python3 mygetnext.py IP地址 用户名 认证算法 认证密钥 加密算法 加密密钥 OID 请求OID的数量')
        print('认证算法支持md5和sha')
        print('加密算法支持3des, des, aes128, aes192, aes256')
        print('例如：')
        print('python3 mygetnext.py 192.168.1.1 user1 sha Cisc0123 des Cisc0123 1.3.6.1.2.1.2.2.1.10.1 10')

