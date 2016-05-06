#!/usr/bin/python3
# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！
import sys
sys.path.append('/usr/local/lib/python3.4/dist-packages/PyQYT/ExtentionPackages')
sys.path.append('/usr/lib/python3.4/site-packages/PyQYT/ExtentionPackages')
sys.path.append('../../ExtentionPackages')

from pysnmp.entity.rfc3413.oneliner import cmdgen
import sys
from io import StringIO

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

    #========================下面的操作在判断安全模型==========================
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
    #========================判断安全模型结束==========================
    errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
        cmdgen.UsmUserData(user, hash_key, cry_key,
                           authProtocol=hashval,
                           privProtocol=cryval),#添加用户，散列密钥，加密密钥，散列协议，加密协议
        cmdgen.UdpTransportTarget((ip, 161)),#添加目标地址和端口号
        oid,#指定oid
        lexicographicMode=True, maxRows=num, ignoreMonIncreasingOid=True#指定最大行数
    )

    if errorIndication:#打印错误
        print(errorIndication)
    else:
        if errorStatus:#打印错误
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
                    oid_get = o.getvalue().strip()#通过print到StringIO进行转码，然后读回
                    o.close()
                    v = StringIO()
                    print(val,file=v)
                    val_get = v.getvalue().strip()#通过print到StringIO进行转码，然后读回
                    v.close()
                    oid_list.append((oid_get,val_get))#添加oid和对应值的信息到oid_list

    return(oid_list)#返回oid_list

if __name__ == '__main__':
    try:
        ip = sys.argv[1]#读取客户输入参数
        user = sys.argv[2]#读取客户输入参数
        hm = sys.argv[3]#读取客户输入参数
        hk = sys.argv[4]#读取客户输入参数
        cm = sys.argv[5]#读取客户输入参数
        ck = sys.argv[6]#读取客户输入参数
        oid = sys.argv[7]#读取客户输入参数
        num = int(sys.argv[8])#读取客户输入参数
        for item in snmpv3_getnext(ip,user,hm,hk,cm,ck,oid,num):
            print('OID: ', item[0], 'VALUE: ', item[1])#从oid_list读取并且打印信息

    except Exception as e:
        #print(e)
        print('参数设置应该如下:')
        print('python3 mygetnext.py IP地址 用户名 认证算法 认证密钥 加密算法 加密密钥 OID 请求OID的数量')
        print('认证算法支持md5和sha')
        print('加密算法支持3des, des, aes128, aes192, aes256')
        print('例如：')
        print('python3 mygetnext.py 192.168.1.1 user1 sha Cisc0123 des Cisc0123 1.3.6.1.2.1.2.2.1.10.1 10')

