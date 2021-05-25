#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: searchCVE.py
@time: 2021/5/2 15:21
@desc: 找出 cve 与 cpe 对应关系,并存入数据库
'''
import ijson


class searchcve(object):
    def __init__(self, filename,):
        self.filename = filename

    def parse_json(self, ):
        cvedict = {}
        with open(self.filename, 'rb') as input_file:
            for cves in ijson.items(input_file, 'CVE_Items.item'):
                cve_id = cves['cve']['CVE_data_meta']['ID']
                cpes = [match
                        for node in cves['configurations']['nodes']
                        for match in node['cpe_match']]

                key = cve_id
                cpelist = []
                for i in range(len(cpes)):
                    try:
                        # value = cpes[i]['cpe23Uri']
                        # print(value)
                        cpelist.append(cpes[i]['cpe23Uri'])
                        cpestr = ",".join(cpelist)
                        value = cpestr
                        cvedict[key] = value
                        # cpelist.append(cvedict)
                    except Exception as e:
                        print("Search error: " + str(e))
        # print(list(cvedict.items()))
        # return list(cvedict.items())
        return cvedict


def main():
    search = searchcve("../cve-feeds/nvdcve-1.1-2016.json",)
    search.parse_json()


if __name__ == '__main__':
    main()
