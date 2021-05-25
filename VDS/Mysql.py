#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: Mysql.py
@time: 2021/5/3 19:04
@desc: 负责查询功能
'''
import pymysql
import traceback
from itertools import chain
from cve_match import CVEmatch


class CPEdb(object):
    def __init__(self):
        self.DB_NAME = 'CPEdb'
        self.TABLE_NAME = 'cpe_and_cpe23'
        config = {
            'host': 'localhost',
            'port': 3306,
            'user': 'root',
            'passwd': 'root',
            'charset': 'utf8'
        }

        conn = pymysql.connect(**config)
        # conn.autocommit(1)

        cursor = conn.cursor()
        self.cursor = cursor
        self.conn = conn
        self.cursor.execute('USE CPEdb')


    def select_cpe23_through_cpe(self, cpe,):
        cpe23list = []
        try:
            sql = "select cpe23 from cpe_and_cpe23 where cpe='{}'".format(cpe)
            self.cursor.execute(sql)
            result = self.cursor.fetchall()
            if result:
                print("该 CPE 对应的 CPE23：" + str(list(chain.from_iterable(result))))
                cpe23list.append(list(chain.from_iterable(result)))
            else:
                print("没有该 cpe !")
                return []
        except:
            traceback.print_exc()
            self.conn.rollback()  # 回滚

        return cpe23list[0]


class CVEdb(object):
    def __init__(self, vendor, product, version):
        self.DB_NAME = 'CVEdb'
        self.TABLE_NAME = 'cve_and_cpe23'
        config = {
            'host': 'localhost',
            'port': 3306,
            'user': 'root',
            'passwd': 'root',
            'charset': 'utf8'
        }

        conn = pymysql.connect(**config)
        # conn.autocommit(1)

        cursor = conn.cursor()
        self.cursor = cursor
        self.conn = conn
        self.cursor.execute('USE CVEdb')

        self.vendor = vendor
        self.product = product
        self.version = version

        self.cvecandidates = []
        self.cvespecifcily = []

        self.match = CVEmatch(self.vendor, self.product, self.version)

    def cvematch(self, ):
        cvespecificilyList = []
        cvecandidaesList = []
        """
        input: cve_feeds, software_CPE23
        output: cve_specially
        software_vendor = software_CPE23.vendor
        software_product = software_CPE23.product
        software_version = software_CPE23.version
        for cve in cve_feeds:
            for cve_vendor,cve_product,cve_version in cve:
                if similar(software_vendor, cve_vendor) 
                    and similar(software_product, cve_product)
                    and same(software_version, cve_version):

                    cve_specially.append(cve)
                if end
            for end    
        for end     

        """
        try:
            sql = "select cve from cve_and_cpe23 where vendor='{}' and product='{}' and version='{}'".format(self.vendor,
                                                                                                             self.product,
                                                                                                             self.version)
            self.cursor.execute(sql)
            result = self.cursor.fetchall()

            # 精确匹配成功
            if result:
                tmp = []
                for i in result:
                    tmp.append(i[0])
                print("精确匹配成功")
                print(tmp)
                cvespecificilyList.append(tmp)
            # 没有version进行summary查找
            else:
                print("精确匹配没有找到")
            #     cvecandidaesList = self.search_summary()

            # version 通配
            tmplist = self.asteriskmatch()
            if tmplist:
                cvespecificilyList.append(tmplist)
        except Exception as e:
            traceback.print_exc()
            self.conn.rollback()  # 回滚


        Flag = 0
        if cvespecificilyList:
            # print("当前cpe23精确匹配的结果：")
            # print(set(self.cvespecifcily))
            Flag += 1
            for i in range(len(cvespecificilyList)):
                self.cvespecifcily.append(cvespecificilyList[i])

        if cvecandidaesList:
            Flag += 1
            for i in range(len(cvecandidaesList)):
                self.cvecandidates.append(cvecandidaesList[i])

        if Flag == 0:
            print("精确匹配和summary查找都没有找到！")
            return [], []
        else:
            if cvecandidaesList:
                print(cvecandidaesList)
            if cvespecificilyList:
                print(cvespecificilyList)
            return cvespecificilyList, cvecandidaesList

    def search_summary(self, ):
        temp = []
        Flag = 0
        print("\n准备进行summary查询:")
        self.cursor.execute('select count(*) from summary')
        count = self.cursor.fetchall()
        for i in range(1, count[0][0]):
            sql = 'select id, cve, summary from summary where id={}'.format(i)
            self.cursor.execute(sql)
            tupe = self.cursor.fetchall()
            # print(tupe[0][2])
            flag, tmplist = self.match.diffsummary(tupe)
            if flag >= 1:
                Flag += 1
            #     print("summary查找成功！")
            #     print(set(tmplist))
                # break
                temp.append(tmplist)
        if Flag!= 0:
            print("\nsummary 查找成功！" + str(temp))
        else:
            print("\nsummary 未找到")
        return temp

    def asteriskmatch(self, ):
        tmplist = []
        print("\n准备进行version通配符查询:")
        sql = "select cve, vendor, product from cve_and_cpe23 where version='*'"
        self.cursor.execute(sql)
        tupes = self.cursor.fetchall()
        for tupe in tupes:
            flag, cvespecifcily = self.match.AsteriskMatch(tupe)
            if flag >= 1:
                print("通配符version查找成功！")
                print(str(tupe[0]))
                tmplist.append(cvespecifcily)
        print("当前version通配结果: " + str(tmplist))
        return tmplist


class Assetdb(object):
    def __init__(self, ):
        self.DB_NAME = 'assetdb'
        self.TABLE_NAME = 'ip'
        config = {
            'host': 'localhost',
            'port': 3306,
            'user': 'root',
            'passwd': 'root',
            'charset': 'utf8'
        }

        conn = pymysql.connect(**config)
        # conn.autocommit(1)

        cursor = conn.cursor()
        self.cursor = cursor
        self.conn = conn
        self.cursor.execute('USE assetdb')

    def select_domain(self, ):
        targetlist = []
        sql = "select count(*) from ip"
        self.cursor.execute(sql)
        count = self.cursor.fetchall()
        print(count[0][0])
        for i in range(2, int(count[0][0])+1):
            query_sql = "select ip from ip where id={}".format(str(i))
            self.cursor.execute(query_sql)
            target = self.cursor.fetchall()
            targetlist.append(target[0][0])
        return targetlist


def main():
    cvedb = CVEdb('BNBSurvey', 'survey.cgi', '5.3')
    cvedict = [('CVE-2020-0001', 'cpe:2.3:o:google:android:8.0:*:*:*:*:*:*:*,cpe:2.3:o:google:android:8.1:*:*:*:*:*:*:*,cpe:2.3:o:google:android:9.0:*:*:*:*:*:*:*,cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*'), ('CVE-2020-0633', 'cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1903:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1909:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*'), ('CVE-2020-0631', 'cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:itanium:*,cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*,cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*,cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1903:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2016:1909:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*')]

    cvedb.cvematch()


if __name__ == '__main__':
    main()