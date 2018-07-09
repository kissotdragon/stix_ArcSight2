#! python2
# Author: John Kennedy
# Email: kissotdragon@gmail.com
# Date: 07/08/2018

import requests
import untangle
import xmltodict
import json
import lxml
from datetime import datetime, timedelta
import pprint, sys, socket, collections, os, types, re, io, time, pytz
from bs4 import BeautifulSoup
from urlparse import urlparse
from optparse import OptionParser
from optparse import BadOptionError
from optparse import AmbiguousOptionError
import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc
from libtaxii.common import generate_message_id
from libtaxii.constants import *
from stix.core import STIXPackage, STIXHeader
from stix.utils.parser import EntityParser
from stix.common import vocabs
from stix.common.vocabs import VocabString
from stix.common.vocabs import IndicatorType
from dateutil.tz import tzutc
from lxml import etree
from xml.etree.ElementTree import XML, XMLParser, tostring, TreeBuilder
from xml.etree import ElementTree as ET

socket.setdefaulttimeout(30)

### SET PROXY
http_proxy  = "http://[username]:[password]@proxy.example.com:8080"
https_proxy = "http://[username]:[password]@proxy.example.com:8080"
ftp_proxy   = "http://[username]:[password]@proxy.example.com:8080"

proxyDict = {
              "http"  : http_proxy,
              "https" : https_proxy,
              "ftp"   : ftp_proxy
            }

#Arcsight = False
Arcsight = True

CONFIG={}

CONFIG['FACILITY'] = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

CONFIG['LEVEL'] = {
        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

### SET SYSLOG SERVER
CONFIG['DESTINATION_IP'] = {
'ip' : '10.0.0.21',
'port' : '514',
}

## SET DESTINATION
dest = CONFIG['DESTINATION_IP']['ip']
dest_port = int(CONFIG['DESTINATION_IP']['port'])

def syslog(message, level=CONFIG['LEVEL']['notice'], facility=CONFIG['FACILITY']['daemon'], host='localhost', port=1514):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '<%d>%s' % (level + facility*8, message)
        sock.sendto(data, (host, port))
        sock.close()

### Set the date delta
date_N_hours_ago = datetime.now() - timedelta(hours=48)
date_now = datetime.now()
args_sts = date_N_hours_ago.strftime("%Y-%m-%d %H:%M:%S")
args_ets = date_now.strftime("%Y-%m-%d %H:%M:%S")

structTime = time.strptime(args_sts,'%Y-%m-%d %H:%M:%S')
begin_ts = datetime(*structTime[:7])
begin_ts = begin_ts.replace(tzinfo=pytz.UTC)

eTime = time.strptime(args_ets,'%Y-%m-%d %H:%M:%S')
end_ts = datetime(*eTime[:7])
end_ts = end_ts.replace(tzinfo=pytz.UTC)

### CREATE THE POLL
## SET Collection Name
poll_req = tm11.PollRequest(message_id=tm11.generate_message_id(),
collection_name='system.Default',
exclusive_begin_timestamp_label=begin_ts,
inclusive_end_timestamp_label=end_ts,
poll_parameters=tm11.PollRequest.PollParameters())

poll_req_xml = poll_req.to_xml()

### SET SOME HEADERS
headrs = [
"Content-Type: application/xml",
"Content-Length: " + str(len(poll_req_xml)),
"User-Agent: TAXII Client Application",
"Accept: application/xml",
"X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1",
"X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1",
"X-TAXII-Protocol: urn:taxii.mitre.org:protocol:https:1.0",
]
head = {
'Content-Type': 'application/xml',
'User-Agent': 'TAXII Client Application',
'Accept': 'application/xml',
'X-TAXII-Accept': 'urn:taxii.mitre.org:message:xml:1.1',
'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:https:1.0'
}

### SET TAXII URL/USERNAME/PASSWORD
taxii_url = ""
taxii_user=''
taxii_password=''

### GET THE DATA
## Remove "proxies" if needed.
response_message = requests.post(taxii_url, proxies=proxyDict ,verify=False, headers=head, data=poll_req_xml, auth=(taxii_user,taxii_password))

### USE BEAUTIFULSOUP TO PARSE IT
soup = BeautifulSoup(response_message.text, "xml")
### FIND ALL OBSERVABLES
print ('Time Range Start: %s | Time Range End: %s ' % ( args_sts, args_ets ))
for child in soup.find_all('Observables'):
    try:
        if child.Observable:
            try:
                if 'e-mail' in child.Observable.Properties["category"]:
                    if child.Observable.Title:
                        myTitle = child.Observable.Title.text
                    else:
                        myTitle = "NH-ISAC Phishing Email"
                    if child.Observable.Description:
                        myDesc = child.Observable.Description.text
                    else:
                        myDesc = "NH-ISAC Malicious Email"
                    myEmail = child.Observable.Properties.Address_Value.text
                    print ('Title: %s | Description: %s | Indicator: %s' % ( myTitle, myDesc, myEmail ))
                    if Arcsight:
                        print ('Email Observable Sent to ArcSight %s' % ( myEmail ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Email'+'|1|suser='+myEmail+' msg=NH-ISAC Malicious Email '+myEmail
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif 'ipv4-addr' in child.Observable.Properties["category"]:
                    if child.Observable.Title:
                        myTitle = child.Observable.Title.text
                    else:
                        myTitle = "NH-ISAC Malicious IP"
                    if child.Observable.Description:
                        myDesc = child.Observable.Description.text
                    else:
                        myDesc = "NH-ISAC Malicious IP"
                    myInd = child.Observable.Properties.Address_Value.text
                    print ('Title: %s | Description: %s | Indicator: %s' % ( myTitle, myDesc, myInd ))
                    if Arcsight:
                        print ('IP Observable Sent to ArcSight %s' % ( myInd ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'IP Address'+'|1|request='+myInd+' shost='+myInd+' msg=NH-ISAC Malicious Domain '+myInd
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif 'URL' in child.Observable.Properties["type"]:
                    if child.Observable.Title:
                        myTitle = child.Observable.Title.text
                    else:
                        myTitle = "NH-ISAC Malicious URL"
                    if child.Observable.Description:
                        myDesc = child.Observable.Description.text
                    else:
                        myDesc = "NH-ISAC Malicious URL"
                    myInd = child.Observable.Properties.Value.text
                    print ('Title: %s | Description: %s | Indicator: %s' % ( myTitle, myDesc, myInd ))
                    u = urlparse(myInd)
                    if Arcsight:
                        print ('URL Observable Sent to ArcSight %s' % ( myInd ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Website'+'|1|request='+myInd+' shost='+u.netloc+' msg=NH-ISAC Malicious Domain '+myInd
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif 'FileObj:FileObjectType' in child.Observable.Properties["type"]:
                    if child.Observable.Title:
                        myTitle = child.Observable.Title.text
                    else:
                        myTitle = "NH-ISAC Malicious File Hash"
                    if child.Observable.Description:
                        myDesc = child.Observable.Description.text
                    else:
                        myDesc = "NH-ISAC Malicious File Hash"
                    myHash = child.Observable.Properties.Hash.Simple_Hash_Value.text
                    myHashType =  child.Observable.Properties.Hash.Simple_Hash_Value.text
                    print ('Title: %s | Description: %s | Indicator: %s' % ( myTitle, myDesc, myHash ))
                    if Arcsight:
						print ('Hash Observable Sent to ArcSight %s' % ( myHash ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Hash'+'|1|cs1='+myHash+' msg=NH-ISAC Malicious File Object: Hash '+myHash
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)
                else:
                    print "Parsing Issue Please research..."
                    print(child)

            except ValueError:
                    print >> sys.stderr, "Could Not Parse Observable"
                    print >> sys.stderr, child
                    raise
    except (TypeError, AttributeError, KeyError):
        pass
		
### FIND ALL INDICATORS
for child in soup.find_all('Indicators'):
    try:
        if child.Indicator:
            try:
                if re.match("mal_url", child.Indicator.Title.text):
                    mal_url = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    url_data = mal_url.split(": ")
                    u = urlparse(url_data[1])
                    if Arcsight:
                        print ('URL Indicator Sent to ArcSight %s' % ( url_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Website'+'|1|request='+url_data[1]+' shost='+u.netloc+' msg=NH-ISAC Malicious Domain|URL '+url_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)
                elif re.match("mal_domain", child.Indicator.Title.text):
                    mal_domain = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    domain_data = mal_domain.split(": ")
                    myDomain = 'http://' + domain_data[1]
                    u = urlparse(domain_data[1])
                    if Arcsight:
                        print ('Domain Indicator Sent to ArcSight %s' % ( domain_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Website'+'|1|request='+domain_data[1]+' shost='+u.netloc+' msg=NH-ISAC Malicious Domain '+domain_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)
                elif re.match("mal_ip", child.Indicator.Title.text):
                    mal_ip = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    ip_data = mal_ip.split(": ")
                    if Arcsight:
                        print ('IP Indicator Sent to ArcSight %s' % ( ip_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Host'+'|1|src='+ip_data[1]+' msg=NH-ISAC Malicious IP '+ip_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif re.match("phish_url", child.Indicator.Title.text):
                    phish_url = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    phish_data = phish_url.split(": ")
                    u = urlparse(phish_data[1])
                    if Arcsight:
                        print ('Phishing URL Indicator Sent to ArcSight %s' % ( phish_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Website'+'|1|request='+phish_data[1]+' shost='+u.netloc+' msg=NH-ISAC Malicious Domain|URL '+phish_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif re.match("phish_email", child.Indicator.Title.text):
                    phish_email = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    email_data = phish_email.split(": ")
                    if Arcsight:
                        print ('Phishing Email Indicator Sent to ArcSight: %s' % ( email_data[1]))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Email'+'|1|suser='+email_data[1]+' msg=NH-ISAC Malicious Email '+email_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)
                elif re.match("c2_ip", child.Indicator.Title.text):
                    c2_ip = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    c2_data = c2_ip.split(": ")
                    if Arcsight:
                        print ('C2 IP Indicator Sent to ArcSight: %s ' % ( c2_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious C2 '+'Host'+'|1|src='+c2_data[1]+' msg=NH-ISAC Malicious C2 IP '+c2_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)
						elif re.match("c2_url", child.Indicator.Title.text):
                    c2_url = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    c2URL_data = c2_url.split(": ")
                    u = urlparse(c2URL_data[1])
                    if Arcsight:
                        print ('C2 URL Indicator Sent to ArcSight: %s ' % ( c2URL_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'C2 Website'+'|1|request='+c2URL_data[1]+' shost='+u.netloc+' msg=NH-ISAC Malicious C2 Domain|URL '+c2URL_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif re.match("phish_domain", child.Indicator.Title.text):
                    phish_domain = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    phishDomain_data = phish_domain.split(": ")
                    myDomain = 'http://' + phishDomain_data[1]
                    u = urlparse(myDomain)
                    if Arcsight:
                        print ('Phishing Domain Indicator Sent to ArcSight %s' % ( phishDomain_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Phishing Website'+'|1|request='+phishDomain_data[1]+' shost='+u.netloc+' msg=NH-ISAC Phishing Domain '+phishDomain_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                elif re.match("suspicious_domain", child.Indicator.Title.text):
                    susp_domain = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    suspd_data = susp_domain.split(": ")
                    myDomain = 'http://' + suspd_data[1]
                    u = urlparse(suspd_data[1])
                    if Arcsight:
                        print ('Suspicious Domain Indicator Sent to ArcSight %s' % ( suspd_data[1] ))
                        cef = 'CEF:0|CE-OSINT|CE-NHISAC|1.0|100|NH-ISAC Known Malicious '+'Suspicious Website'+'|1|request='+suspd_data[1]+' shost='+u.netloc+' msg=NH-ISAC Suspicious Domain '+suspd_data[1]
                        time.sleep(0.02)
                        syslog(cef, host=dest,port=dest_port)

                else:
                    myInd = child.Indicator.Title.text
                    myIndType = child.Indicator.Type.text
                    print ('Unparsed Indicator | Name: %s | Type: %s ' % ( myInd, myIndType ))
            except ValueError:
                print >> sys.stderr, "Could Not Parse Indicator"
                print >> sys.stderr, child
                raise
    except (TypeError, AttributeError, KeyError):
        pass

print "All Done"
sys.exit(0)
