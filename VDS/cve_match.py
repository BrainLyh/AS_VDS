#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: cpe_match.py
@time: 2021/5/6 15:25
@desc: 通过CPE23找到对应CVE
'''

from fuzzywuzzy import fuzz


class CVEmatch(object):
    def __init__(self, vendor23, product23, version23):
        self.vendor23 = vendor23 # 要查找的对象
        self.product23 = product23
        self.version23 = version23

    # 对 summary 进行匹配
    def diffsummary(self,tupe):
        flag = 0
        vendor = []
        product = []
        summary = tupe[0][2]
        cvecandidates = []
        """
        input: cve_feeds, software_CPE23
        output: cve_candidates
        software_vendor = software_CPE23.vendor
        software_product = software_CPE23.product
        for cve in cve_feeds.without_cpe23:
            for cve_description in cve:
                if similar(software_vendor, cve_description) 
                    and similar(software_product, cve_description):
                    cve_candidates.append(cve)
                if end
            for end    
        for end     
        """
        # 分割，重新组合目标
        if '_' in self.vendor23:
            vendor = self.vendor23.split('_')
            vendorreplaceblank = ' '.join(vendor)
            vendor.append(vendorreplaceblank)
        else:
            vendor.append(self.vendor23)

        if '_' in self.product23:
            product = self.product23.split('_')
            productreplaceblank = ' '.join(product)
            product.append(productreplaceblank)
        else:
            product.append(self.product23)

        for i in range(len(vendor)):
            if fuzz.token_set_ratio(summary, vendor[i]) > 95:
                print("vendor相似度达到95:")
                print(vendor[i])
                cvecandidates.append(tupe[0][1])
                print(cvecandidates)
                flag += 1
                break

        for i in range(len(product)):
            if fuzz.token_set_ratio(summary, product[i]) > 95:
                print("product相似度达到95:")
                print(product[i])
                cvecandidates.append(tupe[0][1])
                print(cvecandidates)
                flag += 1
                break

        return flag, cvecandidates

    # 不完全匹配，排除打印错误等
    def typomatch(self, tupe):
        cvecandidates = []
        flag = 0
        cve = tupe[0][0]
        vendor = tupe[0][1]
        product = tupe[0][2]
        version = tupe[0][3]
        # vendor, product 的权重较高,优先匹配
        # 对其使用 Levenshtein 算法是为了排除人为因素导致的误差，例如拼写错误
        if fuzz.token_set_ratio(vendor, self.vendor23) >= 95 and fuzz.token_set_ratio(product, self.product23) >= 95:
            if version == self.version23:
                cvecandidates.append(cve)
            else:
                print("typo match Not found!")
        if cvecandidates:
            flag += 1
            # print("对应CVE：")
            # print(cvecandidates)
        return cvecandidates

    """
    input: cve_feeds, software_CPE23
    output: cve_candidates
    software_vendor = software_CPE23.vendor
    software_product = software_CPE23.product
    for cve in cve_feeds.version_equal_*:
        for cve_description in cve:
            if similar(software_vendor, cve_description) 
                and similar(software_product, cve_description):
                cve_candidates.append(cve)
            if end
        for end    
    for end
    """

    # 对version存在*(通配符)的CVE条目只进行vendor,product匹配
    def AsteriskMatch(self, tupe):
        cvecandidates = []
        flag = 0
        cve = tupe[0]
        vendor = tupe[1]
        product = tupe[2]
        if fuzz.token_set_ratio(vendor, self.vendor23) >= 95 and fuzz.token_set_ratio(product, self.product23) >= 95:
            cvecandidates.append(cve)
        if cvecandidates:
            flag += 1
        return flag, cvecandidates


def main():
    cpe = "cpe:2.3:a:@thi.ng/egf_project:@thi.ng/egf:0.3.0:*:*:*:*:node.js:*:*"
    cvematch = CVEmatch('Linux_kernel', 'Linux_kernel', '0.3.0')
    cvematch.diffsummary()



if __name__ == '__main__':
    main()