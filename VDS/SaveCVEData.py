#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: SaveCVEData.py
@time: 2021/5/8 18:16
@desc: 将 CVE 与对应的 CPE23 数据存储
'''
import pymysql
import traceback
from ParseSummary import ParseSummary
import datetime


class CVEdb(object):
    def __init__(self, filename):
        self.path = filename
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
        self.conn.select_db(self.DB_NAME)

    def init_db(self, ):
        try:
            # 创建数据库
            # self.cursor.execute('DROP DATABASE IF EXISTS CVEdb')  # 如果再执行一次之前创建的表就没了
            # self.cursor.execute('CREATE DATABASE IF NOT EXISTS CVEdb')
            self.cursor.execute('USE CVEdb')

            # self.cursor.execute('DROP TABLE cve_and_cpe23 IF EXISTS')

            # 创建表
            sql = "CREATE TABLE cve_and_cpe23(" \
                  "id int primary key AUTO_INCREMENT NULL," \
                  "cve varchar(80)," \
                  "cpe23 varchar(80)," \
                  "vendor varchar(80)," \
                  "product varchar(80)," \
                  "version varchar(80)" \
                  ")"
            # self.cursor.execute(sql)

            # 创建索引,对 vendor 和 product 来说(and操作)只需一个索引
            # self.cursor.execute("alter table `cve_and_cpe23` add index (vendor);")
            # self.cursor.execute("alter table `cve_and_cpe23` add index (version);")

        except:
            traceback.print_exc()
            self.conn.rollback()  # 回滚

        # return self.conn, self.cursor

    def insert_cveinfo_into_db(self, ):
        parse = ParseSummary(self.path)
        emptydict, cvedict = parse.parsejson()
        print(cvedict)
        return cvedict

    def insert_cve_and_cpe23(self, ):
        cvedict = self.insert_cveinfo_into_db()
        # print(cvedict)
        try:
            for key, value in cvedict.items():
                candidatelist = []
                cpe23list = value.split(",")
                # print(cpe23list)
                for cpe23 in cpe23list:
                    # print(key, cpe23)
                    cpe23unbond = cpe23.split(':')
                    # print(cpeunbond)
                    vendor = cpe23unbond[3]
                    product = cpe23unbond[4]
                    version = cpe23unbond[5]
                    cpetupe = (key, cpe23, vendor, product, version)
                    print(cpetupe)
                    candidatelist.append(cpetupe)


                # 插入数据,采用多行插入速度更快
                sql = 'INSERT INTO cve_and_cpe23 (cve, cpe23, vendor, product, version) ' \
                          'values(%s, %s, %s, %s, %s)'
                self.cursor.executemany(sql, candidatelist)
                    # 查询数据
        except Exception as e:
            print("Save error: " + str(e))

        return


def main():
    start = datetime.datetime.now()
    for i in range(2004, 2022):
        cvedb = CVEdb("../cve-feeds/nvdcve-1.1-2022.json")
        cvedb.init_db()
        # cvedb.insert_cve_and_cpe23()


    end = datetime.datetime.now()
    print("共花费： %s " % str(end - start))

if __name__ == '__main__':
    main()