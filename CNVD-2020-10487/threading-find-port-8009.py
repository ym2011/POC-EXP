#!/usr/bin/env python
# -*- coding: utf-8 -*-
from socket import *
import threading
import time
import os
import re
import requests
import Queue
import requests


lock = threading.Lock()
# 存放内容
http_URL = []

#网站url
http_website  = []
#每个线程分配的url
urlSepList=[]
#分离文件名 给每个线程分一个
def read_file(file_path):
    # 判断文件路径是否存在，如果不存在直接退出，否则读取文件内容
    if not os.path.exists(file_path):
        print('Please confirm correct filepath !')
        sys.exit(0)
    else:
        with open(file_path, 'r') as source:
            for line in source:
                #print(line.rstrip('\r\n').rstrip('\n'))
                http_website.append(line.rstrip('\r\n').rstrip('\n'))

#分离文件名 给每个线程分一个
def separateName(threadCount):
    for i in range(0,len(http_website),int(len(http_website)/threadCount)):
        urlSepList.append(http_website[i:i+int(len(http_website)/threadCount)])

#多线程函数
def multithreading(threadCount):
    separateName(threadCount)#先分离
    for i in range(0,threadCount-1):
        t=threading.Thread(target=run_one_thread,args=(urlSepList[i],))
        t.start()

#每个线程的运作 参数为文件名称的列表
def run_one_thread(url_list):
    port=8009
    for url in url_list:
        ok_f=open("8009.txt","a+")
        try:
            s = socket(AF_INET,SOCK_STREAM)
            s.settimeout(3)
            s.connect((url,port))
            lock.acquire()
            print(url+" is open 8009")
            ok_f.write(url+"\n")
            #print('[+] %d open' % port)
            lock.release()
            s.close()
        except Exception as e:
            #raise e
            pass
        ok_f.close()
if __name__ == '__main__':
    file_str="ip.txt"
    read_file(file_str)
    thread_num=20
    if len(http_website)<thread_num:
        thread_num=len(http_website)
    print(thread_num)
    multithreading(thread_num)
   # print(urlSepList)