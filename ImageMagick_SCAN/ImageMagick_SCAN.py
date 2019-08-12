import os,sys,re
import platform
                        
if len(sys.argv) == 2:
    rootdir = sys.argv[1]
else:
	rootdir = os.getcwd()

sep = '/'
win = 0
if "Windows" in platform.system():
	win = 1
	sep ='\\'

hint = ''
def init_detect():
	global hint
	output1 = os.popen("convert -version").read()
	if "version" not in output1.lower():
		print "There is no ImageMagick library in you system."
		hint = "Although the ImageMagick library in you system is not vulnerable, but you should pay attention to these files:"
		return

	if os.path.exists('exp.png'):
		os.remove('exp.png')

	expcmd = "convert " + """'https://127.0.0.1";|ls "-al'""" + " exp.png"
	print expcmd
	output2 = os.popen(expcmd).read()
	
	if os.path.exists('exp.png'):
		print "Pay attention, the ImageMagick library in your system is vulnerable!!!"
		os.remove('exp.png')
	
def vuln_detect():
	global hint
	print hint
	for parent,dirnames,filenames in os.walk(rootdir):
		for filename in filenames:
			#print filename
			try:
				f = open(parent + sep + filename, "r")
			except Exception,e:
				continue
			else:
				str = f.readline().lower()
				while str:
					if re.search( r"(image|url).+https://.+[;\"]\s*\|\s*", str, re.I) or \
					   re.search(r"image.+\'\s*ephemeral:", str, re.I) or \
					   re.search(r"image.+\'\s*msl:", str, re.I) or \
					   re.search(r"image.+\'\s*label:", str, re.I) or \
					   re.search(r"\'\s*url\s*\(\s*http://", str, re.I):
						if filename != sys.argv[0]:
							print "[ Maybe ] vulnerable file : ", parent+sep+filename
						break
					str = f.readline()
				f.close()
if __name__ == '__main__':
	init_detect()
	vuln_detect()