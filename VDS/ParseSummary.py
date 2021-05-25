#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: ParseSummary.py
@time: 2021/5/10 20:03
@desc: 提取出来那些CVE没有对应CPE的summary
'''
import ijson


class ParseSummary(object):
    def __init__(self, fileath):
        self.filepath = fileath

    def parsejson(self, ):
        cvedict = {}
        emptydict = {}
        with open(self.filepath, 'rb') as input_file:
            for cves in ijson.items(input_file, 'CVE_Items.item'):

                cve_id = cves['cve']['CVE_data_meta']['ID']
                summary = cves['cve']['description']['description_data'][0]['value']
                cpelist = []

                if len(cves['configurations']['nodes']) > 0:
                    for j in range(len(cves['configurations']['nodes'])):
                        node = cves['configurations']['nodes'][j]

                        if len(node['children']) > 0:

                            for i in range(len(node['children'])):
                                # print(cve_id)
                                # print(type(node['children'][i]['cpe_match']))
                                # print(cve_id, node['children'][i]['cpe_match'][0]['cpe23Uri'])
                                for match in range(len(node['children'][i]['cpe_match'])):
                                    cpe = node['children'][i]['cpe_match'][match]['cpe23Uri']
                                    cpelist.append(cpe)
                                    cpe23 = ','.join(cpelist)
                                    cvedict[cve_id] = cpe23

                        for cpes in node['cpe_match']:

                            if 'cpe23Uri' not in cpes.keys():
                                # print("cpe23uri 为空:")
                                # print(cve_id, summary)
                                if summary[0] != '*':
                                    print(summary)
                                    emptydict[cve_id] = summary
                                    # emptylist.append(emptydict)

                            else:
                                cpe = cpes['cpe23Uri']
                                cpelist.append(cpe)
                                # print(len(cpelist))
                                cpestr = ','.join(cpelist)

                                cvedict[cve_id] = cpestr
                                # print(cpestr)

                else:
                    # print("node 为空 " + cve_id)
                    if 'REJECT' not in summary:
                        # print(summary)
                        emptydict[cve_id] = summary

                    # emptylist.append(emptydict)

        # print(emptydict)
        # print(cvedict)
        return emptydict, cvedict



def main():
    parse = ParseSummary("test.json")
    parse.parsejson()


if __name__ == '__main__':
    main()