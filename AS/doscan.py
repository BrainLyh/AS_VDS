#!/usr/bin/env python
# encoding: utf-8
'''
@author: Brian
@file: __init__.py.py
@time: 2021/5/15 15:36
@desc: 
'''

import os
from portscan import Run
# from SDEnumerate.ESD import SDEnumerate


def find_path(path):
    filelist = []
    for filename in os.listdir(path):
        if '_' not in filename:
            filelist.append(filename)
    print("\nDoamin list that waiting for port scan: ")
    print(filelist)

    for path in filelist:
        run = Run(path)
        run.run()


def main():
    flag = True
    while (flag):
        do = input("input 1:SDEnumerate, 2:do port scan, 3:exit :").strip()
        print(do)
        if do == '1':
            param = input("请输入需要查询的域名(支持域名文件)：").strip()
            # sde = SDEnumerate(param)
            # sde.run()
        elif do == '2':
            print(111)
            path = "./SDEnumerate/data"
            find_path(path)
        else:
            flag = False
            exit(0)


if __name__ == '__main__':
    main()