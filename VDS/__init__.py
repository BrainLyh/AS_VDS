#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: __init__.py.py
@time: 2021/5/15 15:37
@desc: 
'''
from useShodanGetCPE import ShodanDomainSearch
from Mysql import CPEdb, CVEdb, Assetdb
import datetime

SHODAN_API_KEY = "********"


class Collection(object):

    def __init__(self, target,):
        self.key = SHODAN_API_KEY
        self.target = target
        # cpe数据库初始化
        self.cpedb = CPEdb()

        self.cpe_or_cpe23 = []
        self.cvespecifily = []
        self.cvecandidate = []

    def select_cve_through_cpe23(self, cpelist):
        for cpe in cpelist:
            cpesplit = cpe.split(':')
            # 完整的cpe23
            if len(cpesplit) > 5:
                vendor = cpesplit[3]
                product = cpesplit[4]
                version = cpesplit[5]
                # print(vendor, product, version)
                print("\n对 " + str(cpe) + '进行CVE查找：')
                cvedb = CVEdb(vendor, product, version)
                cvespecifily, cvecandidate = cvedb.cvematch()

                if cvecandidate:
                    self.cvecandidate.append(cvecandidate)
                    print("\n当前cvecandidate列表: " + str(self.cvecandidate))
                if cvespecifily:
                    self.cvespecifily.append(cvespecifily)
                    print("\n当前cvespecifily: " + str(self.cvespecifily))
            # 缺少version
            else:
                print('\n' + str(cpe) + " version缺失进行summary查找：")
                vendor = cpesplit[3]
                product = cpesplit[4]
                version = ''
                cvedb = CVEdb(vendor, product, version)
                cvecandidates = cvedb.search_summary()
                if cvecandidates:
                    self.cvecandidate.append(cvecandidates)
                    print("\n当前cvecandidate列表: " + str(self.cvecandidate))
        return

    def select_cve(self, ):
        shodan = ShodanDomainSearch(self.key, self.target)
        print("利用 Shodan 得到的目标信息：")
        cpelist, cpe23list = shodan.search()
        print("利用 Shodan 得到的 CPE 列表：")
        print(cpelist, cpe23list)
        flag = 0

        if cpelist:
            flag += 1
            for i in range(len(cpelist)):
                print("\n当前是cpe：" + str(cpelist[i]))
                # print(cpelist[i])
                self.cpe_or_cpe23 = self.cpedb.select_cpe23_through_cpe(cpelist[i],)
                self.select_cve_through_cpe23(self.cpe_or_cpe23)

        if cpe23list:
        # 找到了 cpe23
            flag += 1
            self.select_cve_through_cpe23(cpe23list)

        if flag == 0:
            print("\n没有找到CPE或者CPE23")
            exit(0)
        if self.cvespecifily:
            print("\n最终的精确查找结果：")
            print(self.cvespecifily)
        if self.cvecandidate:
            print("\n最终的summary查找结果：")
            print(self.cvecandidate)

    def savetesult(self, ):
        with open('result.txt', 'w') as f:
            f.write("精确查找结果：")
            f.write(str(self.cvespecifily))
            f.write("summary查找结果： ")
            f.write(str(self.cvecandidate))

def main():
    try:
        start = datetime.datetime.now()
        # 74.208.20.36
        target = "74.208.20.36"
        # assetdb = Assetdb()
        # targetlist = assetdb.select_domain()
        # print(targetlist)
        # for target in targetlist:
        collection = Collection(target,)
        collection.select_cve()
        collection.savetesult()

        end = datetime.datetime.now()
        print("共花费： %s " % str(end - start))
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()
