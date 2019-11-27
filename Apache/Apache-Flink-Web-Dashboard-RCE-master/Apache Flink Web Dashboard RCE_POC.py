#!/usr/bin/env python3
# _*_ coding: utf-8 _*_


"""
auth: bigger.wing@gmail.com
version:
function:
usage:
note:
"""


import os
import subprocess
import requests
from multiprocessing.dummy import Pool as ThreadPool


def get_iplist():
    iplist = []
    with open('iplist', 'r') as file:
        data = file.readlines()
        for item in data:
            ip = item.strip()
            iplist.append(ip)

    return iplist


def check_8081(ip):
    url = 'http://' + ip + ':8081/jar/upload'

    try:
        res = requests.get(url=url, timeout=2)
        data = {
            'msg': res.json(),
            'state': 1,
            'url': url,
            'ip': ip
        }

    except:
        data = {
            'msg': 'Secure',
            'state': 0,
            'ip': ip
        }

    if data['state'] == 1:
        print(data)


if __name__ == '__main__':
    iplist = get_iplist()

    pool = ThreadPool(20)
    pool.map(check_8081, iplist)