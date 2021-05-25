#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: SaveSummary.py
@time: 2021/5/10 19:57
@desc: 将那些CVE没有对应CPE的summary存起来
'''
from ParseSummary import ParseSummary
import pymysql
import traceback
import datetime


class SummaryDB(object):
    def __init__(self, filename):
        self.path = filename
        self.DB_NAME = 'CVEdb'
        self.TABLE_NAME = 'summary'
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

    def init_db(self, ):
        try:
            # 创建数据库
            # self.cursor.execute('DROP DATABASE IF EXISTS SummaryDB')
            # self.cursor.execute('CREATE DATABASE IF NOT EXISTS SummaryDB')
            self.cursor.execute('USE CVEdb')

            # 创建表
            sql = "CREATE TABLE summary(" \
                  "id int primary key AUTO_INCREMENT NULL," \
                  "cve varchar(80)," \
                  "summary MEDIUMTEXT" \
                  ")"
            # self.cursor.execute(sql)

            # 创建索引,对 vendor 和 product 来说(and操作)只需一个索引
            # self.cursor.execute("alter table `summary` add index (summary);")

        except:
            traceback.print_exc()
            self.conn.rollback()  # 回滚

        return self.conn, self.cursor

    # 获得解析的summary
    def summary(self, ):
        parse = ParseSummary(self.path)
        emptydict, cvedict = parse.parsejson()
        summarylist = list(emptydict.items())
        print(summarylist)
        return summarylist

    def insert_cve_and_summary(self, ):
        summarylist = self.summary()
        for i in range(len(summarylist)):
            sql = "insert into summary (cve, summary) values(%s, %s)"
            self.cursor.execute(sql, summarylist[i])

        return

def main():
    start = datetime.datetime.now()
    for i in range(2003, 2022):
        sumdb = SummaryDB("./cve-feeds/nvdcve-1.1-%s.json" % i)
        sumdb.init_db()
        # sumdb.summary()
        # sumdb.insert_cve_and_summary()


    end = datetime.datetime.now()
    print("共花费： %s " % str(end - start))

if __name__ == '__main__':
    main()