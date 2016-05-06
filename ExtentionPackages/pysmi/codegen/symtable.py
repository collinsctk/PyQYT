#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
# Build an internally used symbol table for each passed MIB.
#
import sys
from time import strptime, strftime
from keyword import iskeyword
from pysmi.mibinfo import MibInfo
from pysmi.codegen.base import AbstractCodeGen
from pysmi import error
from pysmi import debug

if sys.version_info[0] > 2:
    unicode = str
    long = int
    def dorepr(s): return repr(s)
else:
    def dorepr(s): return repr(s.encode('utf-8')).decode('utf-8')

class SymtableCodeGen(AbstractCodeGen):
    symsTable = {
      'MODULE-IDENTITY': ('ModuleIdentity',),
      'OBJECT-TYPE': ('MibScalar', 'MibTable', 'MibTableRow', 'MibTableColumn'),
      'NOTIFICATION-TYPE': ('NotificationType',),
      'TEXTUAL-CONVENTION': ('TextualConvention',),
      'MODULE-COMPLIANCE': ('ModuleCompliance',),
      'OBJECT-GROUP': ('ObjectGroup',),
      'NOTIFICATION-GROUP': ('NotificationGroup',),
      'AGENT-CAPABILITIES': ('AgentCapabilities',),
      'OBJECT-IDENTITY': ('ObjectIdentity',),
      'TRAP-TYPE': ('NotificationType',),  # smidump always uses NotificationType
      'BITS': ('Bits',),
    }

    constImports = {
      'SNMPv2-SMI': ('iso',
                     'Bits', # XXX
                     'Integer32', # XXX
                     'TimeTicks', # bug in some IETF MIBs
                     'Counter32', # bug in some IETF MIBs (e.g. DSA-MIB)
                     'Counter64', # bug in some MIBs (e.g.A3COM-HUAWEI-LswINF-MIB)
                     'NOTIFICATION-TYPE', # bug in some MIBs (e.g. A3COM-HUAWEI-DHCPSNOOP-MIB)
                     'Gauge32', # bug in some IETF MIBs (e.g. DSA-MIB)
                     'MODULE-IDENTITY', 'OBJECT-TYPE', 'OBJECT-IDENTITY', 'Unsigned32', 'IpAddress', # XXX
                     'MibIdentifier'), # OBJECT IDENTIFIER
      'SNMPv2-TC': ('DisplayString', 'TEXTUAL-CONVENTION',), # XXX
      'SNMPv2-CONF': ('MODULE-COMPLIANCE', 'NOTIFICATION-GROUP',), # XXX
    }

    baseTypes = ['Integer', 'Integer32', 'Bits', 'ObjectIdentifier', 'OctetString']
    updateDict = lambda x, newitems: x.update(newitems) or x

    commonSyms = {'RFC1155-SMI/RFC1065-SMI':
                     {'internet': [('SNMPv2-SMI', 'internet')],
                       'directory': [('SNMPv2-SMI', 'directory')],
                       'mgmt': [('SNMPv2-SMI', 'mgmt')],
                       'experimental': [('SNMPv2-SMI', 'experimental')],
                       'private': [('SNMPv2-SMI', 'private')],
                       'enterprises': [('SNMPv2-SMI', 'enterprises')],
                       'OBJECT-TYPE': [('SNMPv2-SMI', 'OBJECT-TYPE')],
                       'ObjectName': [('SNMPv2-SMI', 'ObjectName')],
                       'ObjectSyntax': [('SNMPv2-SMI', 'ObjectSyntax')],
                       'SimpleSyntax': [('SNMPv2-SMI', 'SimpleSyntax')],
                       'ApplicationSyntax': [('SNMPv2-SMI', 'ApplicationSyntax')],
                       'NetworkAddress': [('SNMPv2-SMI', 'IpAddress')],
                       'IpAddress': [('SNMPv2-SMI', 'IpAddress')],
                       'Counter': [('SNMPv2-SMI', 'Counter32')],
                       'Gauge': [('SNMPv2-SMI', 'Gauge32')],
                       'TimeTicks': [('SNMPv2-SMI', 'TimeTicks')],
                       'Opaque': [('SNMPv2-SMI', 'Opaque')],
                   },
                   'RFC1158-MIB/RFC1213-MIB':
                     {'mib-2': [('SNMPv2-SMI', 'mib-2')],
                      'DisplayString': [('SNMPv2-TC', 'DisplayString')],
                      'system': [('SNMPv2-MIB', 'system')],
                      'interfaces': [('IF-MIB', 'interfaces')],
                      'ip': [('IP-MIB', 'ip')],
                      'icmp': [('IP-MIB', 'icmp')],
                      'tcp': [('TCP-MIB', 'tcp')],
                      'udp': [('UDP-MIB', 'udp')],
                      'transmission': [('SNMPv2-SMI', 'transmission')],
                      'snmp': [('SNMPv2-MIB', 'snmp')],
                      'sysDescr': [('SNMPv2-MIB', 'sysDescr')],
                      'sysObjectID': [('SNMPv2-MIB', 'sysObjectID')],
                      'sysUpTime': [('SNMPv2-MIB', 'sysUpTime')],
                      'sysContact': [('SNMPv2-MIB', 'sysContact')],
                      'sysName': [('SNMPv2-MIB', 'sysName')],
                      'sysLocation': [('SNMPv2-MIB', 'sysLocation')],
                      'sysServices': [('SNMPv2-MIB', 'sysServices')],
                      'ifNumber': [('IF-MIB', 'ifNumber')],
                      'ifTable': [('IF-MIB', 'ifTable')],
                      'ifEntry': [('IF-MIB', 'ifEntry')],
                      'ifIndex': [('IF-MIB', 'ifIndex')],
                      'ifDescr': [('IF-MIB', 'ifDescr')],
                      'ifType': [('IF-MIB', 'ifType')],
                      'ifMtu': [('IF-MIB', 'ifMtu')],
                      'ifSpeed': [('IF-MIB', 'ifSpeed')],
                      'ifPhysAddress': [('IF-MIB', 'ifPhysAddress')],
                      'ifAdminStatus': [('IF-MIB', 'ifAdminStatus')],
                      'ifOperStatus': [('IF-MIB', 'ifOperStatus')],
                      'ifLastChange': [('IF-MIB', 'ifLastChange')],
                      'ifInOctets': [('IF-MIB', 'ifInOctets')],
                      'ifInUcastPkts': [('IF-MIB', 'ifInUcastPkts')],
                      'ifInNUcastPkts': [('IF-MIB', 'ifInNUcastPkts')],
                      'ifInDiscards': [('IF-MIB', 'ifInDiscards')],
                      'ifInErrors': [('IF-MIB', 'ifInErrors')],
                      'ifInUnknownProtos': [('IF-MIB', 'ifInUnknownProtos')],
                      'ifOutOctets': [('IF-MIB', 'ifOutOctets')],
                      'ifOutUcastPkts': [('IF-MIB', 'ifOutUcastPkts')],
                      'ifOutNUcastPkts': [('IF-MIB', 'ifOutNUcastPkts')],
                      'ifOutDiscards': [('IF-MIB', 'ifOutDiscards')],
                      'ifOutErrors': [('IF-MIB', 'ifOutErrors')],
                      'ifOutQLen': [('IF-MIB', 'ifOutQLen')],
                      'ifSpecific': [('IF-MIB', 'ifSpecific')],
                      'ipForwarding': [('IP-MIB', 'ipForwarding')],
                      'ipDefaultTTL': [('IP-MIB', 'ipDefaultTTL')],
                      'ipInReceives': [('IP-MIB', 'ipInReceives')],
                      'ipInHdrErrors': [('IP-MIB', 'ipInHdrErrors')],
                      'ipInAddrErrors': [('IP-MIB', 'ipInAddrErrors')],
                      'ipForwDatagrams': [('IP-MIB', 'ipForwDatagrams')],
                      'ipInUnknownProtos': [('IP-MIB', 'ipInUnknownProtos')],
                      'ipInDiscards': [('IP-MIB', 'ipInDiscards')],
                      'ipInDelivers': [('IP-MIB', 'ipInDelivers')],
                      'ipOutRequests': [('IP-MIB', 'ipOutRequests')],
                      'ipOutDiscards': [('IP-MIB', 'ipOutDiscards')],
                      'ipOutNoRoutes': [('IP-MIB', 'ipOutNoRoutes')],
                      'ipReasmTimeout': [('IP-MIB', 'ipReasmTimeout')],
                      'ipReasmReqds': [('IP-MIB', 'ipReasmReqds')],
                      'ipReasmOKs': [('IP-MIB', 'ipReasmOKs')],
                      'ipReasmFails': [('IP-MIB', 'ipReasmFails')],
                      'ipFragOKs': [('IP-MIB', 'ipFragOKs')],
                      'ipFragFails': [('IP-MIB', 'ipFragFails')],
                      'ipFragCreates': [('IP-MIB', 'ipFragCreates')],
                      'ipAddrTable': [('IP-MIB', 'ipAddrTable')],
                      'ipAddrEntry': [('IP-MIB', 'ipAddrEntry')],
                      'ipAdEntAddr': [('IP-MIB', 'ipAdEntAddr')],
                      'ipAdEntIfIndex': [('IP-MIB', 'ipAdEntIfIndex')],
                      'ipAdEntNetMask': [('IP-MIB', 'ipAdEntNetMask')],
                      'ipAdEntBcastAddr': [('IP-MIB', 'ipAdEntBcastAddr')],
                      'ipAdEntReasmMaxSize': [('IP-MIB', 'ipAdEntReasmMaxSize')],
                      'ipNetToMediaTable': [('IP-MIB', 'ipNetToMediaTable')],
                      'ipNetToMediaEntry': [('IP-MIB', 'ipNetToMediaEntry')],
                      'ipNetToMediaIfIndex': [('IP-MIB', 'ipNetToMediaIfIndex')],
                      'ipNetToMediaPhysAddress': [('IP-MIB', 'ipNetToMediaPhysAddress')],
                      'ipNetToMediaNetAddress': [('IP-MIB', 'ipNetToMediaNetAddress')],
                      'ipNetToMediaType': [('IP-MIB', 'ipNetToMediaType')],
                      'icmpInMsgs': [('IP-MIB', 'icmpInMsgs')],
                      'icmpInErrors': [('IP-MIB', 'icmpInErrors')],
                      'icmpInDestUnreachs': [('IP-MIB', 'icmpInDestUnreachs')],
                      'icmpInTimeExcds': [('IP-MIB', 'icmpInTimeExcds')],
                      'icmpInParmProbs': [('IP-MIB', 'icmpInParmProbs')],
                      'icmpInSrcQuenchs': [('IP-MIB', 'icmpInSrcQuenchs')],
                      'icmpInRedirects': [('IP-MIB', 'icmpInRedirects')],
                      'icmpInEchos': [('IP-MIB', 'icmpInEchos')],
                      'icmpInEchoReps': [('IP-MIB', 'icmpInEchoReps')],
                      'icmpInTimestamps': [('IP-MIB', 'icmpInTimestamps')],
                      'icmpInTimestampReps': [('IP-MIB', 'icmpInTimestampReps')],
                      'icmpInAddrMasks': [('IP-MIB', 'icmpInAddrMasks')],
                      'icmpInAddrMaskReps': [('IP-MIB', 'icmpInAddrMaskReps')],
                      'icmpOutMsgs': [('IP-MIB', 'icmpOutMsgs')],
                      'icmpOutErrors': [('IP-MIB', 'icmpOutErrors')],
                      'icmpOutDestUnreachs': [('IP-MIB', 'icmpOutDestUnreachs')],
                      'icmpOutTimeExcds': [('IP-MIB', 'icmpOutTimeExcds')],
                      'icmpOutParmProbs': [('IP-MIB', 'icmpOutParmProbs')],
                      'icmpOutSrcQuenchs': [('IP-MIB', 'icmpOutSrcQuenchs')],
                      'icmpOutRedirects': [('IP-MIB', 'icmpOutRedirects')],
                      'icmpOutEchos': [('IP-MIB', 'icmpOutEchos')],
                      'icmpOutEchoReps': [('IP-MIB', 'icmpOutEchoReps')],
                      'icmpOutTimestamps': [('IP-MIB', 'icmpOutTimestamps')],
                      'icmpOutTimestampReps': [('IP-MIB', 'icmpOutTimestampReps')],
                      'icmpOutAddrMasks': [('IP-MIB', 'icmpOutAddrMasks')],
                      'icmpOutAddrMaskReps': [('IP-MIB', 'icmpOutAddrMaskReps')],
                      'tcpRtoAlgorithm': [('TCP-MIB', 'tcpRtoAlgorithm')],
                      'tcpRtoMin': [('TCP-MIB', 'tcpRtoMin')],
                      'tcpRtoMax': [('TCP-MIB', 'tcpRtoMax')],
                      'tcpMaxConn': [('TCP-MIB', 'tcpMaxConn')],
                      'tcpActiveOpens': [('TCP-MIB', 'tcpActiveOpens')],
                      'tcpPassiveOpens': [('TCP-MIB', 'tcpPassiveOpens')],
                      'tcpAttemptFails': [('TCP-MIB', 'tcpAttemptFails')],
                      'tcpEstabResets': [('TCP-MIB', 'tcpEstabResets')],
                      'tcpCurrEstab': [('TCP-MIB', 'tcpCurrEstab')],
                      'tcpInSegs': [('TCP-MIB', 'tcpInSegs')],
                      'tcpOutSegs': [('TCP-MIB', 'tcpOutSegs')],
                      'tcpRetransSegs': [('TCP-MIB', 'tcpRetransSegs')],
                      'tcpConnTable': [('TCP-MIB', 'tcpConnTable')],
                      'tcpConnEntry': [('TCP-MIB', 'tcpConnEntry')],
                      'tcpConnState': [('TCP-MIB', 'tcpConnState')],
                      'tcpConnLocalAddress': [('TCP-MIB', 'tcpConnLocalAddress')],
                      'tcpConnLocalPort': [('TCP-MIB', 'tcpConnLocalPort')],
                      'tcpConnRemAddress': [('TCP-MIB', 'tcpConnRemAddress')],
                      'tcpConnRemPort': [('TCP-MIB', 'tcpConnRemPort')],
                      'tcpInErrs': [('TCP-MIB', 'tcpInErrs')],
                      'tcpOutRsts': [('TCP-MIB', 'tcpOutRsts')],
                      'udpInDatagrams': [('UDP-MIB', 'udpInDatagrams')],
                      'udpNoPorts': [('UDP-MIB', 'udpNoPorts')],
                      'udpInErrors': [('UDP-MIB', 'udpInErrors')],
                      'udpOutDatagrams': [('UDP-MIB', 'udpOutDatagrams')],
                      'udpTable': [('UDP-MIB', 'udpTable')],
                      'udpEntry': [('UDP-MIB', 'udpEntry')],
                      'udpLocalAddress': [('UDP-MIB', 'udpLocalAddress')],
                      'udpLocalPort': [('UDP-MIB', 'udpLocalPort')],
                      'snmpInPkts': [('SNMPv2-MIB', 'snmpInPkts')],
                      'snmpOutPkts': [('SNMPv2-MIB', 'snmpOutPkts')],
                      'snmpInBadVersions': [('SNMPv2-MIB', 'snmpInBadVersions')],
                      'snmpInBadCommunityNames': [('SNMPv2-MIB', 'snmpInBadCommunityNames')],
                      'snmpInBadCommunityUses': [('SNMPv2-MIB', 'snmpInBadCommunityUses')],
                      'snmpInASNParseErrs': [('SNMPv2-MIB', 'snmpInASNParseErrs')],
                      'snmpInTooBigs': [('SNMPv2-MIB', 'snmpInTooBigs')],
                      'snmpInNoSuchNames': [('SNMPv2-MIB', 'snmpInNoSuchNames')],
                      'snmpInBadValues': [('SNMPv2-MIB', 'snmpInBadValues')],
                      'snmpInReadOnlys': [('SNMPv2-MIB', 'snmpInReadOnlys')],
                      'snmpInGenErrs': [('SNMPv2-MIB', 'snmpInGenErrs')],
                      'snmpInTotalReqVars': [('SNMPv2-MIB', 'snmpInTotalReqVars')],
                      'snmpInTotalSetVars': [('SNMPv2-MIB', 'snmpInTotalSetVars')],
                      'snmpInGetRequests': [('SNMPv2-MIB', 'snmpInGetRequests')],
                      'snmpInGetNexts': [('SNMPv2-MIB', 'snmpInGetNexts')],
                      'snmpInSetRequests': [('SNMPv2-MIB', 'snmpInSetRequests')],
                      'snmpInGetResponses': [('SNMPv2-MIB', 'snmpInGetResponses')],
                      'snmpInTraps': [('SNMPv2-MIB', 'snmpInTraps')],
                      'snmpOutTooBigs': [('SNMPv2-MIB', 'snmpOutTooBigs')],
                      'snmpOutNoSuchNames': [('SNMPv2-MIB', 'snmpOutNoSuchNames')],
                      'snmpOutBadValues': [('SNMPv2-MIB', 'snmpOutBadValues')],
                      'snmpOutGenErrs': [('SNMPv2-MIB', 'snmpOutGenErrs')],
                      'snmpOutGetRequests': [('SNMPv2-MIB', 'snmpOutGetRequests')],
                      'snmpOutGetNexts': [('SNMPv2-MIB', 'snmpOutGetNexts')],
                      'snmpOutSetRequests': [('SNMPv2-MIB', 'snmpOutSetRequests')],
                      'snmpOutGetResponses': [('SNMPv2-MIB', 'snmpOutGetResponses')],
                      'snmpOutTraps': [('SNMPv2-MIB', 'snmpOutTraps')],
                      'snmpEnableAuthenTraps': [('SNMPv2-MIB', 'snmpEnableAuthenTraps')]
                   },
    }

    convertImportv2 = {
      'RFC1065-SMI': commonSyms['RFC1155-SMI/RFC1065-SMI'],
      'RFC1155-SMI': commonSyms['RFC1155-SMI/RFC1065-SMI'],
      'RFC1158-MIB': updateDict(dict(commonSyms['RFC1155-SMI/RFC1065-SMI']),
                       (('nullSpecific', [('SNMPv2-SMI', 'zeroDotZero'), ]),
                        ('ipRoutingTable', [('RFC1213-MIB', 'ipRouteTable'), ]),
                        ('ipRouteEntry', [('RFC1213-MIB', 'ipRouteEntry'), ]),
                        ('ipRouteDest', [('RFC1213-MIB', 'ipRouteDest'), ]),
                        ('ipRouteIfIndex', [('RFC1213-MIB', 'ipRouteIfIndex'), ]),
                        ('ipRouteMetric1', [('RFC1213-MIB', 'ipRouteMetric1'), ]),
                        ('ipRouteMetric2', [('RFC1213-MIB', 'ipRouteMetric2'), ]),
                        ('ipRouteMetric3', [('RFC1213-MIB', 'ipRouteMetric3'), ]),
                        ('ipRouteMetric4', [('RFC1213-MIB', 'ipRouteMetric4'), ]),
                        ('ipRouteNextHop', [('RFC1213-MIB', 'ipRouteNextHop'), ]),
                        ('ipRouteType', [('RFC1213-MIB', 'ipRouteType'), ]),
                        ('ipRouteProto', [('RFC1213-MIB', 'ipRouteProto'), ]),
                        ('ipRouteAge', [('RFC1213-MIB', 'ipRouteAge'), ]),
                        ('ipRouteMask', [('RFC1213-MIB', 'ipRouteMask'), ]),
                        ('egpInMsgs', [('RFC1213-MIB', 'egpInMsgs'), ]),
                        ('egpInErrors', [('RFC1213-MIB', 'egpInErrors'), ]),
                        ('egpOutMsgs', [('RFC1213-MIB', 'egpOutMsgs'), ]),
                        ('egpOutErrors', [('RFC1213-MIB', 'egpOutErrors'), ]),
                        ('egpNeighTable', [('RFC1213-MIB', 'egpNeighTable'), ]),
                        ('egpNeighEntry', [('RFC1213-MIB', 'egpNeighEntry'), ]),
                        ('egpNeighState', [('RFC1213-MIB', 'egpNeighState'), ]),
                        ('egpNeighAddr', [('RFC1213-MIB', 'egpNeighAddr'), ]),
                        ('egpNeighAs', [('RFC1213-MIB', 'egpNeighAs'), ]),
                        ('egpNeighInMsgs', [('RFC1213-MIB', 'egpNeighInMsgs'), ]),
                        ('egpNeighInErrs', [('RFC1213-MIB', 'egpNeighInErrs'), ]),
                        ('egpNeighOutMsgs', [('RFC1213-MIB', 'egpNeighOutMsgs'), ]),
                        ('egpNeighOutErrs', [('RFC1213-MIB', 'egpNeighOutErrs'), ]),
                        ('egpNeighInErrMsgs', [('RFC1213-MIB', 'egpNeighInErrMsgs'), ]),
                        ('egpNeighOutErrMsgs', [('RFC1213-MIB', 'egpNeighOutErrMsgs'), ]),
                        ('egpNeighStateUps', [('RFC1213-MIB', 'egpNeighStateUps'), ]),
                        ('egpNeighStateDowns', [('RFC1213-MIB', 'egpNeighStateDowns'), ]),
                        ('egpNeighIntervalHello', [('RFC1213-MIB', 'egpNeighIntervalHello'), ]),
                        ('egpNeighIntervalPoll', [('RFC1213-MIB', 'egpNeighIntervalPoll'), ]),
                        ('egpNeighMode', [('RFC1213-MIB', 'egpNeighMode'), ]),
                        ('egpNeighEventTrigger', [('RFC1213-MIB', 'egpNeighEventTrigger'), ]),
                        ('egpAs', [('RFC1213-MIB', 'egpAs'), ]),
                        ('snmpEnableAuthTraps', [('SNMPv2-MIB', 'snmpEnableAuthenTraps'), ]),
      )),
      'RFC-1212': {'OBJECT-TYPE': [('SNMPv2-SMI', 'OBJECT-TYPE')],
                    # XXX 'IndexSyntax': ???
      },
      'RFC1213-MIB': updateDict(dict(commonSyms['RFC1158-MIB/RFC1213-MIB']),
                        (('PhysAddress', [('SNMPv2-TC', 'PhysAddress'), ]),
      )),
      'RFC-1215': {'TRAP-TYPE': [('SNMPv2-SMI', 'TRAP-TYPE')],
      },
      ### known bugs
      'BRIDGE-MIB': {'MacAddress': [('SNMPv2-TC', 'MacAddress')],
      },
      'CISCO-TC': {'Unsigned32': [('SNMPv2-SMI', 'Unsigned32')],
      },
      'SNMPv2-TC': {'IpAddress': [('SNMPv2-SMI', 'IpAddress')],
      },
      'SNMPv2-SMI': {'TextualConvention': [('SNMPv2-TC', 'TextualConvention')],
      }
    }

    typeClasses = {
      'COUNTER32': 'Counter32',
      'COUNTER64': 'Counter64',
      'GAUGE32': 'Gauge32',
      'INTEGER': 'Integer32', # XXX
      'INTEGER32': 'Integer32',
      'IPADDRESS': 'IpAddress',
      'NETWORKADDRESS': 'IpAddress',
      'OBJECT IDENTIFIER': 'ObjectIdentifier',
      'OCTET STRING': 'OctetString',
      'OPAQUE': 'Opaque',
      'TIMETICKS': 'TimeTicks',
      'UNSIGNED32': 'Unsigned32',
      'Counter': 'Counter32',
      'Gauge': 'Gauge32',
      'NetworkAddress': 'IpAddress', # RFC1065-SMI, RFC1155-SMI -> SNMPv2-SMI
      'nullSpecific': 'zeroDotZero', # RFC1158-MIB -> SNMPv2-SMI
      'ipRoutingTable': 'ipRouteTable', # RFC1158-MIB -> RFC1213-MIB
      'snmpEnableAuthTraps': 'snmpEnableAuthenTraps'  # RFC1158-MIB -> SNMPv2-MIB
    }

    smiv1IdxTypes = ['INTEGER', 'OCTET STRING', 'IPADDRESS', 'NETWORKADDRESS']
    ifTextStr = 'if mibBuilder.loadTexts: '
    indent = ' '*4
    fakeidx = 1000 # starting index for fake symbols

    def __init__(self):
        self._rows = set()
        self._cols = {} # k, v = name, datatype
        self._exports = set()
#    self._presentedSyms = set()
        self._postponedSyms = {} # k, v = symbol, (parents, properties)
        self._parentOids = set()
        self._importMap = {} # k, v = symbol, MIB
        self._symsOrder = []
        self._out = {} # k, v = symbol, properties
        self.moduleName = ['DUMMY']
        self.genRules = {'text': 1}

    def symTrans(self, symbol):
        if symbol in self.symsTable:
            return self.symsTable[symbol]
        return symbol,

    def transOpers(self, symbol):
        if iskeyword(symbol):
            symbol = 'pysmi_' + symbol
        return symbol.replace('-', '_')

    def isBinary(self, s):
        return isinstance(s, (str, unicode)) and s[0] == '\'' \
                                             and s[-2:] in ('\'b', '\'B')

    def isHex(self, s):
        return isinstance(s, (str, unicode)) and s[0] == '\'' \
                                             and s[-2:] in ('\'h', '\'H')

    def str2int(self, s):
        if self.isBinary(s):
            if s[1:-2]:
                i = int(s[1:-2], 2)
            else:
                raise error.PySmiSemanticError('empty binary string to int conversion')
        elif self.isHex(s):
            if s[1:-2]:
                i = int(s[1:-2], 16)
            else:
                raise error.PySmiSemanticError('empty hex string to int conversion')
        else:
            i = int(s)
        return i

    def prepData(self, pdata, classmode=0):
        data = []
        for el in pdata:
            if not isinstance(el, tuple):
                data.append(el)
            elif len(el) == 1:
                data.append(el[0])
            else:
                data.append(self.handlersTable[el[0]](self, self.prepData(el[1:], classmode=classmode), classmode=classmode)
                )
        return data

    def genImports(self, imports):
        # convertion to SNMPv2
        toDel = []
        for module in list(imports):
            if module in self.convertImportv2:
                for symbol in imports[module]:
                    if symbol in self.convertImportv2[module]:
                        toDel.append((module, symbol))
                        for newImport in self.convertImportv2[module][symbol]:
                            newModule, newSymbol = newImport
                            if newModule in imports:
                                imports[newModule].append(newSymbol)
                            else:
                                imports[newModule] = [newSymbol]
        # removing converted symbols
        for d in toDel:
            imports[d[0]].remove(d[1])
        # merging mib and constant imports
        for module in self.constImports:
            if module in imports:
                imports[module] += self.constImports[module]
            else:
                imports[module] = self.constImports[module]

        for module in sorted(imports):
            symbols = ()
            for symbol in set(imports[module]):
                symbols += self.symTrans(symbol)
            if symbols:
#        self._presentedSyms = self._presentedSyms.union([self.transOpers(s) for s in symbols])
                self._importMap.update([(self.transOpers(s), module) for s in symbols])
        return {}, tuple(sorted(imports))

    def allParentsExists(self, parents):
        parentsExists = True
        for parent in parents:
            if not (parent in self._out or \
                    parent in self._importMap or \
                    parent in self.baseTypes or \
                    parent in ('MibTable', 'MibTableRow', 'MibTableColumn') or \
                    parent in self._rows):
                parentsExists = False
                break
        return parentsExists

    def regSym(self, symbol, symProps, parents=[]):
        if symbol in self._out or symbol in self._postponedSyms: # add to strict mode - or symbol in self._importMap:
            raise error.PySmiSemanticError('Duplicate symbol found: %s' % symbol)
        if self.allParentsExists(parents):
            self._out[symbol] = symProps
            self._symsOrder.append(symbol)
            self.regPostponedSyms()
        else:
            self._postponedSyms[symbol] = (parents, symProps)

    def regPostponedSyms(self):
        regedSyms = []
        for sym, val in self._postponedSyms.items():
            parents, symProps = val
            if self.allParentsExists(parents):
                self._out[sym] = symProps
                self._symsOrder.append(sym)
                regedSyms.append(sym)
        for sym in regedSyms:
            self._postponedSyms.pop(sym)

### Clause handlers
    def genAgentCapabilities(self, data, classmode=0):
        origName, description, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'AgentCapabilities',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genModuleIdentity(self, data, classmode=0):
        origName, lastUpdated, organization, contactInfo, description, revisions, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'ModuleIdentity',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genModuleCompliance(self, data, classmode=0):
        origName, description, compliances, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'ModuleCompliance',
                    'oid': oid,
                    'origName': origName}
        self.regSym(pysmiName, symProps)

    def genNotificationGroup(self, data, classmode=0):
        origName, objects, description, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'NotificationGroup',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genNotificationType(self, data, classmode=0):
        origName, objects, description, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'NotificationType',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genObjectGroup(self, data, classmode=0):
        origName, objects, description, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'ObjectGroup',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genObjectIdentity(self, data, classmode=0):
        origName, description, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'ObjectIdentity',
                    'oid': oid,
                    'origName': origName,
        }
        self.regSym(pysmiName, symProps)

    def genObjectType(self, data, classmode=0):
        origName, syntax, units, maxaccess, description, augmention, index, defval, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'ObjectType',
                    'oid': oid,
                    'syntax': syntax, # (type, module), subtype
                    'origName': origName,
        }
        parents = [syntax[0][0]]
        if augmention:
            parents.append(self.transOpers(augmention))
        if defval: # XXX
            symProps['defval'] = defval
        if index and index[1]:
            namepart, fakeIndexes, fakeSymSyntax = index
            for fakeIdx, fakeSyntax in zip(fakeIndexes, fakeSymSyntax):
                fakeName = namepart + str(fakeIdx)
                fakeSymProps = {'type': 'fakeColumn',
                                'oid': oid + (fakeIdx,),
                                'syntax': fakeSyntax,
                                'origName': fakeName}
                self.regSym(fakeName, fakeSymProps)
        self.regSym(pysmiName, symProps, parents)

    def genTrapType(self, data, classmode=0):
        origName, enterprise, variables, description, value = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'NotificationType',
                    'oid': enterprise + (0, value),
                    'origName': origName}
        self.regSym(pysmiName, symProps)

    def genTypeDeclaration(self, data, classmode=0):
        origName, declaration = data
        pysmiName = self.transOpers(origName)
        if declaration:
            parentType, attrs = declaration
            if parentType: # skipping SEQUENCE case
                symProps = {'type': 'TypeDeclaration',
                            'syntax': declaration, # (type, module), subtype
                            'origName': origName}
                self.regSym(pysmiName, symProps, [declaration[0][0]])

    def genValueDeclaration(self, data, classmode=0):
        origName, oid = data
        pysmiName = self.transOpers(origName)
        symProps = {'type': 'MibIdentifier',
                    'oid': oid,
                    'origName': origName}
        self.regSym(pysmiName, symProps)

### Subparts generation functions
    def genBitNames(self, data, classmode=0):
        names = data[0]
        return names
        # done

    def genBits(self, data, classmode=0):
        bits = data[0]
        return ('Bits', ''), bits
        # done

    def genCompliances(self, data, classmode=0):
        return ''

    def genConceptualTable(self, data, classmode=0):
        row = data[0]
        if row[0] and row[0][0]:
            self._rows.add(self.transOpers(row[0][0]))
        return ('MibTable', ''), ''
        # done

    def genContactInfo(self, data, classmode=0):
        return ''

    def genDisplayHint(self, data, classmode=0):
        return ''

    def genDefVal(self, data, classmode=0): # XXX should be fixed, see pysnmp.py
        defval = data[0]
        if isinstance(defval, (int, long)): # number
            val = str(defval)
        elif self.isHex(defval): # hex
            val = 'hexValue="' + defval[1:-2] + '"' #not working for Integer baseTypes
        elif self.isBinary(defval): # binary
            binval = defval[1:-2]
            hexval = binval and hex(int(binval, 2))[2:] or ''
            val = 'hexValue="' + hexval + '"'
        elif isinstance(defval, list): # bits list
            val = defval
        elif defval[0] == defval[-1] and defval[0] == '"': # quoted strimg
            val = dorepr(defval[1:-1])
        else: # symbol (oid as defval) or name for enumeration member
            if defval in self._out or defval in self._importMap:
                val = defval + '.getName()'
            else:
                val = dorepr(defval)
        return val

    def genDescription(self, data, classmode=0):
        return ''

    def genEnumSpec(self, data, classmode=0):
        return self.genBits(data, classmode=classmode)[1]

    def genIndex(self, data, classmode=0):
        indexes = data[0]
        fakeIdxName = 'pysmiFakeCol'
        fakeIndexes, fakeSymsSyntax = [], []
        for idx in indexes:
            idxName = idx[1]
            if idxName in self.smiv1IdxTypes: # SMIv1 support
                idxType = idxName
                objType = self.typeClasses.get(idxType, idxType)
                objType = self.transOpers(objType)
                fakeIndexes.append(self.fakeidx)
                fakeSymsSyntax.append((('MibTableColumn', ''), objType))
                self.fakeidx += 1
        return fakeIdxName, fakeIndexes, fakeSymsSyntax

    def genIntegerSubType(self, data, classmode=0):
        return ''

    def genMaxAccess(self, data, classmode=0):
        return ''

    def genOctetStringSubType(self, data, classmode=0):
        return ''

    def genOid(self, data, classmode=0):
        out = ()
        for el in data[0]:
            if isinstance(el, (str, unicode)):
                parent = self.transOpers(el)
                self._parentOids.add(parent)
                out += ((parent, self._importMap.get(parent, self.moduleName[0])),)
            elif isinstance(el, (int, long)):
                out += (el,)
            elif isinstance(el, tuple):
                out += (el[1],) # XXX Do we need to create a new object el[0]?
            else:
                raise error.PySmiSemanticError('unknown datatype for OID: %s' % el)
        return out

    def genObjects(self, data, classmode=0):
        return ''

    def genTime(self, data, classmode=0):
        return ''

    def genLastUpdated(self, data, classmode=0):
        return ''

    def genOrganization(self, data, classmode=0):
        return ''

    def genRevisions(self, data, classmode=0):
        return ''

    def genRow(self, data, classmode=0):
        row = data[0]
        row = self.transOpers(row)
        return row in self._rows and (('MibTableRow', ''), '') or self.genSimpleSyntax(data, classmode=classmode)

    def genSequence(self, data, classmode=0):
        cols = data[0]
        self._cols.update(cols)
        return '', ''

    def genSimpleSyntax(self, data, classmode=0):
        objType = data[0]
        module = ''
        objType = self.typeClasses.get(objType, objType)
        objType = self.transOpers(objType)
        if objType not in self.baseTypes:
            module = self._importMap.get(objType, self.moduleName[0])
        subtype = len(data) == 2 and data[1] or ''
        return (objType, module), subtype

    def genTypeDeclarationRHS(self, data, classmode=0):
        if len(data) == 1:
            parentType, attrs = data[0] # just syntax
        else:
            # Textual convention
            display, syntax = data
            parentType, attrs = syntax
        return parentType, attrs

    def genUnits(self, data, classmode=0):
        return ''

    handlersTable = {
      'agentCapabilitiesClause': genAgentCapabilities,
      'moduleIdentityClause': genModuleIdentity,
      'moduleComplianceClause': genModuleCompliance,
      'notificationGroupClause': genNotificationGroup,
      'notificationTypeClause': genNotificationType,
      'objectGroupClause': genObjectGroup,
      'objectIdentityClause': genObjectIdentity,
      'objectTypeClause': genObjectType,
      'trapTypeClause': genTrapType,
      'typeDeclaration': genTypeDeclaration,
      'valueDeclaration': genValueDeclaration,

      'ApplicationSyntax': genSimpleSyntax,
      'BitNames': genBitNames,
      'BITS': genBits,
      'ComplianceModules': genCompliances,
      'conceptualTable': genConceptualTable,
      'CONTACT-INFO': genContactInfo,
      'DISPLAY-HINT': genDisplayHint,
      'DEFVAL': genDefVal,
      'DESCRIPTION': genDescription,
      'enumSpec': genEnumSpec,
      'INDEX': genIndex,
      'integerSubType': genIntegerSubType,
      'MaxAccessPart': genMaxAccess,
      'Notifications': genObjects,
      'octetStringSubType': genOctetStringSubType,
      'objectIdentifier': genOid,
      'Objects': genObjects,
      'LAST-UPDATED': genLastUpdated,
      'ORGANIZATION': genOrganization,
      'Revisions' : genRevisions,
      'row': genRow,
      'SEQUENCE': genSequence,
      'SimpleSyntax': genSimpleSyntax,
      'typeDeclarationRHS': genTypeDeclarationRHS,
      'UNITS': genUnits,
      'VarTypes': genObjects,
    }

    def genCode(self, ast, symbolTable, **kwargs):
        self.genRules['text'] = kwargs.get('genTexts', False)
        self._rows.clear()
        self._cols.clear()
        self._parentOids.clear()
        self._symsOrder = []
        self._postponedSyms.clear()
        self._importMap.clear()
        self._out = {} # should be new object, do not use `clear` method
        self.moduleName[0], moduleOid, imports, declarations = ast
        out, importedModules = self.genImports(imports and imports or {})
        for declr in declarations and declarations or []:
            if declr:
                clausetype = declr[0]
                classmode = clausetype == 'typeDeclaration'
                self.handlersTable[declr[0]](self, self.prepData(declr[1:], classmode), classmode)
        if self._postponedSyms:
            raise error.PySmiSemanticError('Unknown parents for symbols: %s' % ', '.join(self._postponedSyms))
        for sym in self._parentOids:
            if sym not in self._out and sym not in self._importMap:
                raise error.PySmiSemanticError('Unknown parent symbol: %s' % sym)
        self._out['_symtable_order'] = list(self._symsOrder)
        self._out['_symtable_cols'] = list(self._cols)
        self._out['_symtable_rows'] = list(self._rows)
        debug.logger & debug.flagCodegen and debug.logger('canonical MIB name %s (%s), imported MIB(s) %s, Symbol table size %s symbols' % (self.moduleName[0], moduleOid, ','.join(importedModules) or '<none>', len(self._out)))
        return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([ x for x in importedModules])), self._out
