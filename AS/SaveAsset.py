#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: SaveAsset.py
@time: 2021/5/15 17:10
@desc: 
'''
import pymysql
import traceback
import requests


class SaveAsset(object):
    def __init__(self,):
        self.KEY = 'SCU174755Ted7bb5fd24f19a0c9dfdb2aa7e875a0460ab05acb91c0'
        self.DB_NAME = 'assetdb'
        self.TABLE_NAME = 'domaininfo'
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
            # self.cursor.execute('DROP DATABASE IF EXISTS Assetdb')  # 如果再执行一次之前创建的表就没了
            # self.cursor.execute('CREATE DATABASE IF NOT EXISTS Assetdb')
            self.cursor.execute('USE assetdb')

            # self.cursor.execute('DROP TABLE ip IF EXISTS')

            # 创建表
            sql = "CREATE TABLE domaininfo(" \
                  "id int primary key AUTO_INCREMENT NULL," \
                  "domain varchar(80)," \
                  "ip varchar(80)," \
                  "port varchar(80)," \
                  "service varchar(80)" \
                  ")"
            # self.cursor.execute(sql)
            #
            # 创建索引,对 vendor 和 product 来说(and操作)只需一个索引
            # self.cursor.execute("alter table `ip` add index (ip);")

        except:
            traceback.print_exc()
            self.conn.rollback()  # 回滚

        # return self.conn, self.cursor

    def insert_ipinfo(self, tupe):
        sql = "INSERT INTO domaininfo (domain, ip, port, service) values ({}, {}, {}, {})"
        select_sql = "select count(*) from domianinfo where ip='{}' and port='{}"
        for info in tupe:
            print(info)
            self.cursor.execute(select_sql.format(info[1], info[2]))
            count = self.cursor.fetchall()
            if count[0][0] != 0:
                self.cursor.execute(sql)
                self.send_message(tupe[0], tupe[1])
        # self.cursor.executemany(sql, tupe)
        return

    def send_message(self, domain, ip):
        url = "https://sc.ftqq.com/" + self.KEY + ".send?text=主人！" + str(domain) +" 又双叒叕发现新资产了~ " + str(ip)
        requests.get(url)


def main():
    saveinfo = SaveAsset()
    tupe = [('baidu', '110.242.69.193', '13389', 'ms-wbt-server'), ('baidu', '110.242.69.192', '80', 'ms-wbt-server')]
    saveinfo.init_db()
    saveinfo.insert_ipinfo(tupe)

if __name__ == '__main__':
    main()