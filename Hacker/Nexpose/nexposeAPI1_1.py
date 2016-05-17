import urllib.request as urllib2
import random
import base64
import ssl
from xml.dom.minidom import Document
import xml.etree.ElementTree as ET

class Connection():
    def __init__(self, server, port, username, password):
        """ Connection Class init call """
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.url = 'https://{0}:{1}'.format(self.server,self.port)
        self.api = '/api/1.1/xml'
        self.authtoken = ''
        self.response = None
        self.sync_id = ''

        #force urllib2 to not use a proxy
        proxy_handler = urllib2.ProxyHandler({})
        opener = urllib2.build_opener(proxy_handler)
        urllib2.install_opener(opener)
        self.login()

    #Gets called in __init__
    def login(self):
        """ logs you into the device """
        doc = Document()
        LoginRequest = doc.createElement('LoginRequest')
        doc.appendChild(LoginRequest)

        #if it has a token it adds it to the request 
        if(self.authtoken != ''):
            LoginRequest.setAttribute('session-id',self.authtoken)
            LoginRequest.setAttribute('sync-id', self.sync_id)
        else:
            LoginRequest.setAttribute('user-id', str(self.username))
            LoginRequest.setAttribute('password', str(self.password))
        
        #makes request and returns response
        
        data = doc.toprettyxml(indent = '    ')

        request = urllib2.Request(self.url + self.api, data.encode())
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = ET.fromstring(response.read().decode())
   
        # response = request("Login", {'user-id' : self.username, 'password' : self.password})
        self.authtoken = response.get('session-id')
        self.response = response
        self.sync_id = str(random.randint(1, 65535))
        return response

    def siteListing(self):
        doc = Document()
        SiteListingRequest = doc.createElement('SiteListingRequest')
        doc.appendChild(SiteListingRequest)

        SiteListingRequest.setAttribute('session-id', self.authtoken)

        data = doc.toprettyxml(indent = '    ')

        request = urllib2.Request(self.url + self.api, data.encode())
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = ET.fromstring(response.read().decode())

        for c in response.getchildren():
            print('name => ', c.get('name'), ', ', 'id => ', c.get('id'), ', ', 'riskfactor => ', c.get('riskfactor'), ', ', 'riskscore => ', c.get('riskscore'), ', ', 'description => ', c.get('description'))

    def siteDeviceListing(self, site_id):
        doc = Document()
        SiteDeviceListingRequest = doc.createElement('SiteDeviceListingRequest')
        doc.appendChild(SiteDeviceListingRequest)

        SiteDeviceListingRequest.setAttribute('session-id', self.authtoken)
        SiteDeviceListingRequest.setAttribute('site-id', str(site_id))

        data = doc.toprettyxml(indent = '    ')

        request = urllib2.Request(self.url + self.api, data.encode())
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = ET.fromstring(response.read().decode())

        for c in response.getchildren():
                for cc in c.getchildren():
                    print('address => ', cc.get('address'), ', ', 'id => ', cc.get('id'), ', ', 'riskfactor => ', cc.get('riskfactor'), ', ', 'riskscore => ', cc.get('riskscore'))

    def engineListing(self):
        doc = Document()
        EngineListingRequest = doc.createElement('EngineListingRequest')
        doc.appendChild(EngineListingRequest)

        EngineListingRequest.setAttribute('session-id', self.authtoken)

        data = doc.toprettyxml(indent = '    ')

        request = urllib2.Request(self.url + self.api, data.encode())
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = ET.fromstring(response.read().decode())

        for c in response.getchildren():
            print('id => ', c.get('id'), ', ', 'status => ', c.get('status'), ', ', 'scope => ', c.get('scope'), ', ', 'address => ', c.get('address'), 'name => ', c.get('name'), ', ', 'port => ', c.get('port'))

    def scanStatistics(self, scan_id):
        doc = Document()
        ScanStatisticsRequest = doc.createElement('ScanStatisticsRequest')
        doc.appendChild(ScanStatisticsRequest)

        ScanStatisticsRequest.setAttribute('session-id', self.authtoken)
        ScanStatisticsRequest.setAttribute('engine-id', self.sync_id)
        ScanStatisticsRequest.setAttribute('scan-id', str(scan_id))

        data = doc.toprettyxml(indent = '    ')

        request = urllib2.Request(self.url + self.api, data.encode())
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = ET.fromstring(response.read().decode())

        for c in response.getchildren():
            print('*'*99)
            print('*'*99)
            print('site-id => ', c.get('site-id'), ', ', 'endTime => ', c.get('endTime'), ', ', 'startTime => ', c.get('startTime'), ', ', 'status => ', c.get('status'), ', ', c.get('status'), ', ', 'scan-id => ', c.get('scan-id'), ', ', 'name', c.get('name'), ', ', 'engine-id => ', c.get('engine-id'))
            print('-'*99)
            print('-'*99)
            for cc in c.getchildren():
                #print(cc.keys())
                if cc.get('severity'):
                    print('severity => ', cc.get('severity'), ', ', 'count => ', cc.get('count'), ', ', 'status => ', cc.get('status'))
                elif cc.get('other'):
                    print('filtered => ', cc.get('filtered'), ', ', 'dead => ', cc.get('dead'), ', ', 'live => ', cc.get('live'), ', ', 'unresolved => ', cc.get('unresolved'), 'other => ', cc.get('other'))
                else:
                    print('status => ', cc.get('status'), ', ', 'count => ', cc.get('count'))

if __name__ == '__main__':
    myNexpose = Connection('192.168.220.136', '3780', 'nxadmin', 'nxpassword')
    myNexpose.siteListing()
    myNexpose.siteDeviceListing(3)
    myNexpose.engineListing()
    myNexpose.scanStatistics(1)
    myNexpose.scanStatistics(3)

