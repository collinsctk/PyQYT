#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#本脚由亁颐堂现任明教教主编写，用于乾颐盾Python课程！
#教主QQ:605658506
#亁颐堂官网www.qytang.com
#乾颐盾是由亁颐堂现任明教教主开发的综合性安全课程
#包括传统网络安全（防火墙，IPS...）与Python语言和黑客渗透课程！

from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

def cbFun(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))
        if msgVer in api.protoModules:
            pMod = api.protoModules[msgVer]
        else:
            print('Unsupported SNMP version %s' % msgVer)
            return
        reqMsg, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=pMod.Message(),
            )
        print('Notification message from %s:%s: ' % (
            transportDomain, transportAddress
            )
        )
        reqPDU = pMod.apiMessage.getPDU(reqMsg)
        if reqPDU.isSameTypeWith(pMod.TrapPDU()):
            if msgVer == api.protoVersion1:
                print('Enterprise: %s' % (
                    pMod.apiTrapPDU.getEnterprise(reqPDU).prettyPrint()
                    )
                )
                print('Agent Address: %s' % (
                    pMod.apiTrapPDU.getAgentAddr(reqPDU).prettyPrint()
                    )
                )
                print('Generic Trap: %s' % (
                    pMod.apiTrapPDU.getGenericTrap(reqPDU).prettyPrint()
                    )
                )
                print('Specific Trap: %s' % (
                    pMod.apiTrapPDU.getSpecificTrap(reqPDU).prettyPrint()
                    )
                )
                print('Uptime: %s' % (
                    pMod.apiTrapPDU.getTimeStamp(reqPDU).prettyPrint()
                    )
                )
                varBinds = pMod.apiTrapPDU.getVarBindList(reqPDU)
            else:
                varBinds = pMod.apiPDU.getVarBindList(reqPDU)
            print('Var-binds:')
            for oid, val in varBinds:
                print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
    return wholeMsg

transportDispatcher = AsynsockDispatcher()

transportDispatcher.registerRecvCbFun(cbFun)

# UDP/IPv4
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openServerMode(('202.100.1.138', 162))
)

transportDispatcher.jobStarted(1)

try:
    # Dispatcher will never finish as job#1 never reaches zero
    transportDispatcher.runDispatcher()
except:
    transportDispatcher.closeDispatcher()
    raise