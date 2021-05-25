#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: ShadonApi.py
@time: 2021/4/21 15:29
@desc:
'''
import shodan
import requests

CPEList = []


class ShodanDomainSearch(object):
    def __init__(self, key, target):
        self.key = key
        self.target = target


    def search(self, ):
        SHODAN_API_KEY = self.key
        target = self.target
        CPEList = []
        CPE23List = []
        api = shodan.Shodan(SHODAN_API_KEY)
        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY
        try:
            # First we need to resolve our targets domain to an IP
            resolved = requests.get(dnsResolve)
            # print(resolved.json())
            hostIP = resolved.json()[target]

            # Then we need to do a Shodan search on that IP
            host = api.host(hostIP)
            # print(host)
            print("IP: %s" % host['ip_str'])
            print("Organization: %s" % host.get('org', 'n/a'))
            print("Operating System: %s \n" % host.get('os', 'n/a'))

            # Print all banners
            for item in host['data']:
                print("Port: %s" % item['port'])
                # print("Banner: %s" % item['data'])
                print("CPE: %s\n" % item['cpe'])
                print("CPE23: %s\n" % item['cpe23'])
                CPEList = item['cpe']
                CPE23List = item['cpe23']

            # print(CPEList)
            # [['cpe:/a:apache:http_server:2.4.18'], ['cpe:/a:apache:http_server:2.4.18'], ['cpe:/a:openbsd:openssh:7.2p2
            # Ubuntu-4ubuntu2.8']]
        except:
            'An error occured'
        return CPEList, CPE23List


def main():
    # SHODAN_API_KEY = "E4QhbTa02HZPmlwxWbY9jG8mUobLJlUn"
    target = "137.128.91.34.bc.googleusercontent.com"
    # shodan = ShodanDomainSearch(SHODAN_API_KEY, target)
    # shodan.search()

if __name__ == '__main__':
    main()