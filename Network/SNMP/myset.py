#!/usr/bin/python3
# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import rfc1902
import sys

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# Setup transport endpoint and bind it with security settings yielding
# a target name (choose one entry depending of the transport needed).
# UDP/IPv4
config.addSocketTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)

# Error/response reciever
def cbFun(sendRequestHandle,
          errorIndication, errorStatus, errorIndex,
          varBindTable, cbCtx):
    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
            )
        )
    else:
        for oid, val in varBindTable:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))

def snmpv3_set(ip='',user='',hash_meth=None,hash_key=None,cry_meth=None,cry_key=None,oid='',customerString=''):
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
    model = None

    config.addTargetAddr(
        snmpEngine, 'yourDevice', 
        udp.domainName, (ip, 161),
        'my-creds'
    )
    #NoAuthNoPriv
    if hash_meth == None and cry_meth == None:
        hashval = config.usmNoAuthProtocol
        cryval = config.usmNoPrivProtocol
        model = 'noAuthNoPriv'
    #AuthNoPriv
    elif hash_meth != None and cry_meth == None:
    	if hash_meth == 'md5':
    		hashval = config.usmHMACMD5AuthProtocol
    	elif hash_meth == 'sha':
    		hashval = config.usmHMACSHAAuthProtocol
    	else:
    		print('哈希算法必须是md5 or sha!')
    		return
    	cryval = config.usmNoPrivProtocol
    	model = 'authNoPriv'
    #AuthPriv
    elif hash_meth != None and cry_meth != None:
    	if hash_meth == 'md5':
    		hashval = config.usmHMACMD5AuthProtocol
    	elif hash_meth == 'sha':
    		hashval = config.usmHMACSHAAuthProtocol
    	else:
    		print('哈希算法必须是md5 or sha!')
    		return
    	if cry_meth == '3des':
    		cryval = config.usm3DESEDEPrivProtocol
    	elif cry_meth == 'des':
    		cryval = config.usmDESPrivProtocol
    	elif cry_meth == 'aes128':
    		cryval = config.usmAesCfb128Protocol
    	elif cry_meth == 'aes192':
    		cryval = config.usmAesCfb192Protocol
    	elif cry_meth == 'aes256':
    		cryval = config.usmAesCfb256Protocol
    	else:
    		print('加密算法必须是3des, des, aes128, aes192 or aes256 !')
    		return
    	model = 'authPriv'
    #提供的参数不符合标准时给出提示
    else:
    	print('三种USM: NoAuthNoPriv, AuthNoPriv, AuthPriv.。请选择其中一种。')
    	return

    config.addV3User(
        snmpEngine, user,
        hashval, hash_key,
        cryval, cry_key
    )
    config.addTargetParams(snmpEngine, 'my-creds', user, model)
    
    # Prepare and send a request message
    cmdgen.SetCommandGenerator().sendReq(
        snmpEngine,
        'yourDevice',
        ( (oid, rfc1902.OctetString(customerString)), ),
        cbFun
    )

    # Run I/O dispatcher which would send pending queries and process responses
    snmpEngine.transportDispatcher.runDispatcher()

if __name__ == '__main__':
    try:
        ip = sys.argv[1]
        user = sys.argv[2]
        hm = sys.argv[3]
        hk = sys.argv[4]
        cm = sys.argv[5]
        ck = sys.argv[6]
        oid = sys.argv[7]
        customerString = sys.argv[8]
        snmpv3_set(ip,user,hm,hk,cm,ck,oid,customerString)
    except:
        print('参数设置应该如下:')
        print('python3 myset.py IP地址 用户名 认证算法 认证密钥 加密算法 加密密钥 OID 赋值')
        print('认证算法支持md5和sha')
        print('加密算法支持3des, des, aes128, aes192, aes256')
        print('例如：')
        print('python3 myset.py 192.168.1.1 user1 sha Cisc0123 des Cisc0123 1.3.6.1.2.1.1.5.0 GNSR1')
