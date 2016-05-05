#!/usr/bin/python3
# -*- coding=utf-8 -*-
#本模块由乾颐堂陈家栋编写，用于乾颐盾Python课程！
#QQ: 594284672
#亁颐堂官网www.qytang.com
#乾颐盾课程包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
#from sendmail import sendTrapInfo
import sys
import re

# Create SNMP engine with autogenernated engineID and pre-bound
snmpEngine = engine.SnmpEngine()

config.addSocketTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('202.100.1.138', 162))
)

#Callback function for receiving notifications
def cbFun(snmpEngine,
          stateReference,
          contextEngineId, contextName,
          varBinds,
          cbCtx):
#    print('Notification received, ContextEngineId "%s", ContextName "%s"' % (
#        contextEngineId.prettyPrint(), contextName.prettyPrint()
#        )
#    )
    for name, val in varBinds:
#        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        name = str(name)
        val = str(val)
        trapInfo = ''
        Interface = ''
#        print(name)
#        print(val)
        #interface up and down！
        if '1.3.6.1.2.1.2.2.1.2.2' in name:
            Interface = name
            print('路由器接口:' + val, end = '', flush = True)
        if '1.3.6.1.4.1.9.2.2.1.1.20.2' in name:
            if re.match('.*down.*', val):
                trapInfo = '接口 ' + Interface + '管理Down'
                print(' 管理Down！') 
            elif re.match('.*up.*', val):
                trapInfo = '接口 ' + Interface + '管理UP'
                print(' 管理UP！')
        #cpu util in last 5s, rising threshold
        if '1.3.6.1.4.1.9.9.109.1.1.1.1.10.1' in name:
            trapInfo = '过去5秒的CPU利用率是 ' + val + '%'
            print('过去5秒的CPU利用率是 ' + val + '%')
        #falling threshold
#        elif '9.9.109.1.2.4.1.4.1.1' in name:
#            trapInfo = 'CPU利用率已经低于 ' + val + '%'
#            print('CPU利用率已经低于 ' + val + '%')
        #ipsec tunnel start
        elif '1.3.6.1.4.1.9.9.171.2.0.7' in val:
            trapInfo = 'ipsec tunnel start'
            print('ipsec tunnel start')
        #ipsec tunnel stop
        elif '1.3.6.1.4.1.9.9.171.2.0.8' in val:
            trapInfo = 'ipsec tunnel stop'
            print('ipsec tunnel stop')
        #ipsla destination reachability inspection
        elif '9.9.42.1.2.19.1.9.1' in name:
            if '1' in val:
                trapInfo = 'R2不可达!'
                print('R2不可达!')
            else:
                trapInfo = 'R2可达!'
                print('R2可达!')
#        if trapInfo != '':
#            sendTrapInfo(trapInfo)

def snmpv3_trap(user='',hash_meth=None,hash_key=None,cry_meth=None,cry_key=None,engineid=''):
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

    #NoAuthNoPriv
    if hash_meth == None and cry_meth == None:
        hashval = config.usmNoAuthProtocol
        cryval = config.usmNoPrivProtocol
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
    #提供的参数不符合标准时给出提示
    else:
    	print('三种USM: NoAuthNoPriv, AuthNoPriv, AuthPriv.。请选择其中一种。')
    	return

    # SNMPv3/USM setup
    # user: usr-md5-des, auth: MD5, priv DES, contextEngineId: 8000000001020304
    # this USM entry is used for TRAP receiving purposes
    config.addV3User(
        snmpEngine, user,
        hashval, hash_key,
        cryval, cry_key,
        contextEngineId=v2c.OctetString(hexValue=engineid)
    )

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    snmpEngine.transportDispatcher.jobStarted(1) # this job would never finish

    # Run I/O dispatcher which would receive queries and send confirmations
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
        raise

if __name__ == '__main__':
    try:
        user = sys.argv[1]
        hm = sys.argv[2]
        hk = sys.argv[3]
        cm = sys.argv[4]
        ck = sys.argv[5]
        engineid = sys.argv[6]
        snmpv3_trap(user,hm,hk,cm,ck,engineid)
    except:
        print('参数设置应该如下:')
        print('python3 mytrap.py 用户名 认证算法 认证密钥 加密算法 加密密钥 engineID')
        print('认证算法支持md5和sha')
        print('加密算法支持3des, des, aes128, aes192, aes256')
        print('例如：')
        print('sudo python3 mytrap.py user1 sha Cisc0123 des Cisc0123 800000090300CA011B280000')

