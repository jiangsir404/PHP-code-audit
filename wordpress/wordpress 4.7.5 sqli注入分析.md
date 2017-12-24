在wordpress版本<=4.7.5的版本中爆出了一个sqli注入漏洞，漏洞发生在WP的后台上传图片的位置，通过修改图片在数据库中的参数，以及利用php的sprintf函数的特性，在删除图片时，导致'单引号的逃逸。漏洞利用较为困难。 


跟踪调试文件， 先来到upload.php 删除图片的地方：

```
case 'delete':
	if ( !isset( $post_ids ) )
		break;
	foreach ( (array) $post_ids as $post_id_del ) {
		if ( !current_user_can( 'delete_post', $post_id_del ) )
			wp_die( __( 'Sorry, you are not allowed to delete this item.' ) );

		if ( !wp_delete_attachment( $post_id_del ) )
			wp_die( __( 'Error in deleting.' ) );
	}
	$location = add_query_arg( 'deleted', count( $post_ids ), $location );
	break;
```


这之前有两次验证_wpnonce的地方，因此一定要得到_wpnonce才能继续下去

进入`wp_delete_attachment( $post_id_del )` 函数， $post_id_del是图片的postid

在post.php 4778行的wp_delete_attachement函数的地方， 调用了delete_metadata 函数，

    delete_metadata( 'post', null, '_thumbnail_id', $post_id, true );
漏洞触发点主要在wp-includes/meta.php 的 delete_metadata函数里面， 有如下代码:

```
if ( $delete_all ) {
	$value_clause = '';
	if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
		$value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
	}

	$object_ids = $wpdb->get_col( $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key ) );
}
```

该语句执行的sql语句是下面这句，调用prepare函数把$meta_key 传给$s参数位置， 但该语句存在明显的字符拼接：$value_clause

    $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key )
    

我们来看下$value_clause拼接的参数：


    $value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
	}

拼接的参数同样调用了prepare函数，我们来看下prepare函数:

```
public function prepare( $query, $args ) {
	if ( is_null( $query ) )
		return;

	// This is not meant to be foolproof -- but it will catch obviously incorrect usage.
	if ( strpos( $query, '%' ) === false ) {
		_doing_it_wrong( 'wpdb::prepare', sprintf( __( 'The query argument of %s must have a placeholder.' ), 'wpdb::prepare()' ), '3.9.0' );
	}

	$args = func_get_args();
	array_shift( $args );
	// If args were passed as an array (as in vsprintf), move them up
	if ( isset( $args[0] ) && is_array($args[0]) )
		$args = $args[0];
	$query = str_replace( "'%s'", '%s', $query ); // in case someone mistakenly already singlequoted it
	$query = str_replace( '"%s"', '%s', $query ); // doublequote unquoting
	$query = preg_replace( '|(?<!%)%f|' , '%F', $query ); // Force floats to be locale unaware
	$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote the strings, avoiding escaped strings like %%s
	array_walk( $args, array( $this, 'escape_by_ref' ) );
	return @vsprintf( $query, $args );
}
```

有意思的是prepare函数先把`'%s'`替换为`%s`,再把`%s` 替换为`'%s'`, 然后调用vsprintf函数格式化字符串



我们来看下sprintf(vsprintf同sprintf)函数的语法

```
<?php
$s = 'monkey';
$t = 'many monkeys';

printf("[%010s]\n",   $s); 
printf("[%'#10s]\n",  $s); 
printf("[%\'#10s]\n",  $s);
printf("[%'110s]\n",  $s); 
?>

>>>
[0000monkey]
[####monkey]
[1111monkey]
['#10s]
```

可以看到sprintf 中的占位符`%` 后面如果是单引号，那么单引号后的一个字符会作为padding填充字符串。


如果我们改变meta_value的值位`22%1$%s and sleep(3)#`

经过第一个vsprintf的处理后变成

    AND meta_value = '22%1$'%s' and sleep(3)#'
    
第一次拼接后又进入一次sprintf函数，此时的sql语句为:


    "SELECT $type_column FROM $table WHERE meta_key = %s AND meta_value = '22%1$'%s' and sleep(3)#'", $meta_key
    

经过prepare处理后的语句为:

    "SELECT $type_column FROM $table WHERE meta_key = '_thumbnail_id' AND meta_value = '22_thumbnail_id' and sleep(3)#'"
    


格式化后把`%1$'%s` 替换为`_thumbnail_id`(单引号后面的%被当作一个padding字符了，而不是占位符), 这样就逃逸出了一个单引号了，这个SQL注入不会报错，只能使用延时注入，而且需要后台的上传权限，所以利用起来比较困难。



### vsprintf更广泛的漏洞利用，不检查字符类型

vprintf/printf还有一个更加严重的问题，对格式化的字符类型没做检查。


在php的格式化字符串中，%后的一个字符(除了'%',%%相当于转义了%)会被当作`字符类型`，而被吃掉，单引号，斜杠\也不例外。

翻看源码, `ext/standard/formatted_print.c`

```
switch (format[inpos]) {
	case 's': {
		zend_string *t;
		zend_string *str = zval_get_tmp_string(tmp, &t);
		php_sprintf_appendstring(&result, &outpos,
								 ZSTR_VAL(str),
								 width, precision, padding,
								 alignment,
								 ZSTR_LEN(str),
								 0, expprec, 0);
		zend_tmp_string_release(t);
		break;
	}

	case 'd':
		php_sprintf_appendint(&result, &outpos,
							  zval_get_long(tmp),
							  width, padding, alignment,
							  always_sign);
		break;

	case 'u':
		php_sprintf_appenduint(&result, &outpos,
							  zval_get_long(tmp),
							  width, padding, alignment);
		break;

	case 'g':
	case 'G':
	case 'e':
	case 'E':
	case 'f':
	case 'F':
		php_sprintf_appenddouble(&result, &outpos,
								 zval_get_double(tmp),
								 width, padding, alignment,
								 precision, adjusting,
								 format[inpos], always_sign
								);
		break;

	case 'c':
		php_sprintf_appendchar(&result, &outpos,
							(char) zval_get_long(tmp));
		break;

	case 'o':
		php_sprintf_append2n(&result, &outpos,
							 zval_get_long(tmp),
							 width, padding, alignment, 3,
							 hexchars, expprec);
		break;

	case 'x':
		php_sprintf_append2n(&result, &outpos,
							 zval_get_long(tmp),
							 width, padding, alignment, 4,
							 hexchars, expprec);
		break;

	case 'X':
		php_sprintf_append2n(&result, &outpos,
							 zval_get_long(tmp),
							 width, padding, alignment, 4,
							 HEXCHARS, expprec);
		break;

	case 'b':
		php_sprintf_append2n(&result, &outpos,
							 zval_get_long(tmp),
							 width, padding, alignment, 1,
							 hexchars, expprec);
		break;

	case '%':
		php_sprintf_appendchar(&result, &outpos, '%');

		break;
	default:
		break;
}

```

可以看到， php源码中只对15种类型做了匹配， 其他字符类型都直接break了，php未做任何处理，直接跳过，所以导致了这个问题


没做字符类型检测的最大危害就是它可以吃掉一个转义符`\`,  如果%后面出现一个`\`,那么php会把`\`当作一个格式化字符的类型而吃掉`\`,  最后`%\`（或`%1$\`）被替换为空
```
<?php

$input = addslashes("%1$' and 1=1#");
echo $input;
echo "\n";
$b = sprintf("AND b='%s'",$input);
echo $b;
echo "\n";
$sql = sprintf("select * from t where a='%s' $b",'admin');
echo $sql;

>>>
%1$\' and 1=1#
AND b='%1$\' and 1=1#'
select * from t where a='admin' AND b='' and 1=1#'
```

格式字符%后面会吃掉一个`\`即`%1$\`被替换为空，逃逸出来一个单引号，造成注入.


### 总结

漏洞利用条件

1. sql语句进行了字符拼接
2. 拼接语句和原sql语句都用了vsprintf/sprintf 函数来格式化字符串






### 官方补丁

在wordpress4.7.6的修复中是这样的，prepare函数;

```
$query = str_replace( "'%s'", '%s', $query ); // in case someone mistakenly already singlequoted it
$query = str_replace( '"%s"', '%s', $query ); // doublequote unquoting
$query = preg_replace( '|(?<!%)%f|' , '%F', $query ); // Force floats to be locale unaware
$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote the strings, avoiding escaped strings like %%s
$query = preg_replace( '/%(?:%|$|([^dsF]))/', '%%\\1', $query ); // escape any unescaped percents 
array_walk( $args, array( $this, 'escape_by_ref' ) );
return @vsprintf( $query, $args );
```

只是多了一行：`$query = preg_replace( '/%(?:%|$|([^dsF]))/', '%%\\1', $query );`  

这个正则的意思就是只允许 %后面出现dsF 这三种字符类型， 其他字符类型都替换为`%%\\1`,  而且还禁止了`%`, `$` 这种参数定位， 基本meta_value 参数是完全过滤掉了

然而补丁是可以被绕过的, 补丁的思路是正确的， 然而官方只是修复了格式化字类型没有检测的错误，用白名单对字符类型进行过滤， 却并没有修复prepare两次格式化字符串的漏洞，导致补丁可以进一步被绕过，  如下demo:

```
function prepare($query,$args){
	$query = str_replace( "'%s'", '%s', $query );
	$query = preg_replace( '|(?<!%)%s|', "'%s'", $query );
	$query = preg_replace( '/%(?:%|$|([^dsF]))/', '%%\\1', $query );
	// preg_match('/%(?:%|$|([^dsF]))/',$query,$matchs);
	// var_dump($matchs);
	$query = vsprintf($query, $args);
	return $query;
}

$meta_value = ' %s ';
$query = " and meta_value= %s ";
$query = prepare($query,$meta_value);
echo $query;

$meta_key = ['dump',' or 1=1 #'];
$sql = "select * from table where meta_key = %s $query";
$sql = prepare($sql,$meta_key);
echo $sql;

>>>
 and meta_value= ' %s ' 
select * from table where meta_key = 'dump'  and meta_value= ' ' or 1=1 #' '
```

meta_value 只是传入一个简单的` %s `,(注意前后两个空格,否则无法绕过第一个替换), 符合白名单的要求，然后在`meta_key`的位置传入payload: ` or 1=1 /*` ,  meta_value 传入的%s经过两次格式化字符串后变成`'' %s ''`, 自动闭合了前一个单引号，导致绕过


在wordpress 4.7.7中已经修复了该问题, 补丁如下。 

```
$allowed_format = '(?:[1-9][0-9]*[$])?[-+0-9]*(?: |0|\'.)?[-+0-9]*(?:\.[0-9]+)?';

$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
$query = preg_replace( '/(?<!%)%s/', "'%s'", $query ); // Quote the strings, avoiding escaped strings like %%s.
$query = preg_replace( "/(?<!%)(%($allowed_format)?f)/" , '%\\2F', $query ); // Force floats to be locale unaware.
$query = preg_replace( "/%(?:%|$|(?!($allowed_format)?[sdF]))/", '%%\\1', $query ); // Escape any unescaped percents.
// Count the number of valid placeholders in the query.
$placeholders = preg_match_all( "/(^|[^%]|(%%)+)%($allowed_format)?[sdF]/", $query, $matches );
if ( count( $args ) !== $placeholders ) {
	if ( 1 === $placeholders && $passed_as_array ) {
		// If the passed query only expected one argument, but the wrong number of arguments were sent as an array, bail.
		wp_load_translations_early();
		_doing_it_wrong( 'wpdb::prepare', __( 'The query only expected one placeholder, but an array of multiple placeholders was sent.' ), '4.9.0' );
		return;
	} else {
		/*
		 * If we don't have the right number of placeholders, but they were passed as individual arguments,
		 * or we were expecting multiple arguments in an array, throw a warning.
		 */
		wp_load_translations_early();
		_doing_it_wrong( 'wpdb::prepare',
			/* translators: 1: number of placeholders, 2: number of arguments passed */
			sprintf( __( 'The query does not contain the correct number of placeholders (%1$d) for the number of arguments passed (%2$d).' ),
				$placeholders,
				count( $args ) ),
			'4.8.3'
		);
	}
}
array_walk( $args, array( $this, 'escape_by_ref' ) );
$query = @vsprintf( $query, $args );
return $this->add_placeholder_escape( $query );
}
```


参考: https://paper.seebug.org/386/

https://lorexxar.cn/2017/10/25/wordpress/