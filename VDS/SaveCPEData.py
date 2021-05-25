#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: SaveData.py
@time: 2021/5/8 17:38
@desc: 将 CPE 与对应的 CPE23 数据存入 mysql
'''
from parseXML import ParseXML
import pymysql
import traceback
import datetime


class CPEdb(object):
    def __init__(self, XMLpath):
        self.XMLpath = XMLpath
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

        self.cpe23list = []

    # 初始化数据库
    def init_db(self, ):

        try:
            # 创建数据库
            self.cursor.execute('DROP DATABASE IF EXISTS %s' % self.DB_NAME)
            self.cursor.execute('CREATE DATABASE IF NOT EXISTS %s' % self.DB_NAME)
            self.conn.select_db(self.DB_NAME)

            # 创建表
            self.cursor.execute('CREATE TABLE %s(id int primary key AUTO_INCREMENT NULL,'
                           'cpe23 varchar(80),'
                           'cpe varchar(80))' % self.TABLE_NAME)

            # 创建 cpe 索引
            self.cursor.execute('ALTER TABLE `cpe_and_cpe23` ADD INDEX (cpe)')
        except:
            traceback.print_exc()
            self.conn.rollback()  # 回滚

        return self.conn, self.cursor

    def insert_cpe23_and_cpe(self, cpedict, conn, cursor):

        try:
            # 插入数据,采用多行插入速度更快
            sql = 'INSERT INTO cpe_and_cpe23 (cpe23, cpe) values(%s, %s)'
            cursor.executemany(sql, cpedict)
            # 查询数据
            # cursor.execute("SELECT * FROM %s" % self.TABLE_NAME)
            # print("成功插入 CPE 和 CPE23 : ")
            # print(cursor.fetchall())
        except:
            traceback.print_exc()
            conn.rollback()  # 回滚

    def extract_cpe_and_cpe23(self, ):
        # return CPE dict
        parsexml = ParseXML(self.XMLpath)

        return parsexml.parseXML()

    def insert_data_into_db(self, ):
        start = datetime.datetime.now()
        CPEdict = self.extract_cpe_and_cpe23()
        # print(CPEdict)
        # [('cpe:2.3:/a:apache:http_server:2.4.18', 'cpe:/a:apache:http_server:2.4.18'),]
        self.insert_cpe23_and_cpe(CPEdict, self.conn, self.cursor)
        end = datetime.datetime.now()
        print("插入共花费： %s " % str(end - start))


def main():
    XMLpath = "official-cpe-dictionary_v2.3.xml"
    cpedb = CPEdb(XMLpath)
    cpedb.init_db()
    cpedb.insert_data_into_db()


if __name__ == '__main__':
    main()