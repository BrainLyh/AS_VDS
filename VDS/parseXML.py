#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: parseXML.py
@time: 2021/4/29 17:26
@desc: Extracting CPEs from XML file is that to find CVE correspondingly
'''

import xml.etree.cElementTree as ET
import urllib.parse as parse


class ParseXML(object):
    def __init__(self, path):
        self.path = path

    def parseXML(self, ):
        cpeList = []

        context = ET.iterparse(self.path, events=("start", "end"))
        cpeDict = {}
        for event, elem in context:
            value = elem.attrib
            # print(type(value))
            tag = elem.tag
            # print(tag)
            if event == "start":
                if tag == '{http://cpe.mitre.org/dictionary/2.0}cpe-item':
                    # print(value)  # key
                    cpe = value.values()
                    cpe = parse.unquote(list(cpe)[0])
                    cpeList.append(cpe)
                elif tag == '{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item':
                    # print(value)  # value
                    cpe = value.values()
                    cpe = parse.unquote(list(cpe)[0])
                    cpeList.append(cpe)
        # print(cpeList)
        # 为了键值对能够对应，采用逆序并控制步长
        for i in range(1, len(cpeList), 2)[::-1]:
            key = cpeList[i]
            value = cpeList[i-1]
            cpeDict[key] = value
            # key:value
            # cpe:2.3:a:\@thi.ng\/egf_project:\@thi.ng\/egf:0.3.0:*:*:*:*:node.js:*:*
            # cpe:/a:@thi.ng/egf_project:@thi.ng/egf:0.3.0::~~~node.js~~
        return list(cpeDict.items())
