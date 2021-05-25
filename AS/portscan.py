#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: IP-ports.py
@time: 2021/2/5 10:58
@desc: 
'''

import re
import nmap
import os
import time
import requests
import chardet
from queue import Queue
from multiprocessing.dummy import Pool as ThreadPool
from SaveAsset import SaveAsset

ports = ['80', '443', '3389', '3306']  # 默认扫描端口


class Scan():
    def __init__(self, queue):
        self._queue = queue  # url 队列
        self.ports = ports
        self.result = []

    # 入口
    def go_scan(self, port):
        while not self._queue.empty():
            ip = self._queue.get()
            print(str(ip) + " is going to scan ...")
            self.masccan(ip)
            self.nmap_scan(ip, port)
            # self.write_result()

        return

    # 调用nmap进行扫描
    def nmap_scan(self, host, port):
        nmap_scan = nmap.PortScanner()
        try:
            ret = nmap_scan.scan(host, port, arguments='-Pn -sS --script=banner')
            service_name = ret['scan'][host]['tcp'][int(port)]['name']

            if 'http' in service_name or service_name == 'sun-answerbook' or 'unknown' in service_name:
                if service_name == 'https' or service_name == 'https-alt':
                    scan_url = 'https://{}:{}'.format(host, port)
                    title = self.get_title(scan_url)
                    service_name = '{}(title:{})'.format(service_name, title)
                else:
                    scan_url = 'http://{}:{}'.format(host, port)
                    title = self.get_title(scan_url)
                    service_name = '{}(title:{})'.format(service_name, title)
            # result = '{}:{} {}'.format(host, port, service_name)
            tupe = (host, port, service_name)
            self.result.append(tupe)
            print(self.result)
        except Exception as e:
            print(str(e))
            print("Please check the nmap command..." + nmap_scan.command_line())
        print(self.result)
        return self.result

    def get_title(self, host):
        try:
            requests.packages.urllib3.disable_warnings()  # 忽略 https 不安全警告
            r = requests.get(host, timeout=5, verify=False)
            r_detectencode = chardet.detect(r.content)  # 得到编码格式
            actual_encode = r_detectencode['encoding']
            content = r.content.decode(actual_encode)
            response = re.findall(u'<title>(.*?)</title>', content, re.S)
            # print(response)
            if response == []:
                return None
            else:
                title = response[0].encode(actual_encode).decode('utf-8')
                banner = r.headers['server']
                return title, banner
        except Exception as e:
            print(str(e))

    # 调用 masccan 得到目标主机开放端口
    def masccan(self, host):
        port_list = []
        ports1 = []  # 临时存放
        os.system('../masscan/bin/masscan ' + host + ' -p 1-65535 -oJ masscan.json --rate 2000')
        with open("./masscan.json", 'r') as f:
            for line in f.readlines():
                if line.startswith('{ '):
                    temp = re.findall(r'{\"port\": (.*?),', line)
                    port = temp[0]
                    port_list.append(port)
        if len(port_list) > 50:
            port_list.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
        else:
            ports1.extend(port_list)  # 小于50则放到总端口列表里
            self.ports = list(set(ports1))

    def write_result(self,):
        save = SaveAsset()
        save.insert_ipinfo(self.result)

        return

    def threadpool(self):
        pool = ThreadPool(processes=50)
        try:
            pool.map(self.go_scan, self.ports)
        except Exception as e:
            print(e)

        pool.close()
        pool.join()


class Run(object, ):
    def __init__(self, path):
        self.domain = path
        self.filepath = os.path.abspath(os.path.dirname(__file__)) + "\SDEnumerate\data\\" + path

    def run(self,):
        print(self.domain)
        print(self.filepath)
        if os.path.isfile(self.filepath):
            queue = Queue()
            url_list = []
            with open(self.filepath) as f:
                for i in f.readlines():
                    result = re.findall(r'\d+\.\d+\.\d+\.\d+', i.strip())
                    url_list += result
            url_list = list(set(url_list))
            print("urls are as follow...")
            print(str(url_list))
            start_time = time.time()
            for url in url_list:
                queue.put(url)
            scan = Scan(queue)
            scan.threadpool()
            end_time = time.time()
            print('Multiprocess Scanning Completed in  ' + str(end_time-start_time))
        else:
            exit("路径不存在！")

if __name__ == '__main__':
    path = ''
    run(path)