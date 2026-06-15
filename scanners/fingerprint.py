# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web指纹识别模块
功能：识别目标网站的CMS、服务器、编程语言等信息
含反黑名单机制: 限速/随机延迟/UA轮换/封禁检测
"""

import re
import random
import time
import threading
import requests
import urllib3
from colorama import Fore, Style, init

# 禁用SSL警告（避免大量警告信息干扰）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


# ===== 反黑名单：User-Agent池 =====
UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
]


class FingerprintScanner:
    """
    Web指纹识别器（含反黑名单机制）
    
    反封禁策略:
        - 随机请求延迟 (0.5~2s)
        - User-Agent自动轮换
        - 请求频率限制
        - 封禁检测与自动冷却
    """
    
    # ===== 封禁检测特征 =====
    BAN_INDICATORS = [
        'captcha', '验证码', '人机验证', 'recaptcha', 'hcaptcha',
        'access denied', 'forbidden', '请求过于频繁', 'rate limit',
        'too many requests', 'blocked', '拦截', '您的访问被限制',
        '安全防护', 'waf', 'cloudflare', '防护系统',
    ]
    
    # CMS指纹规则库
    CMS_RULES = {
        'WordPress': {
            'headers': ['x-powered-by: php'],
            'body': ['wp-content', 'wp-includes', '/wordpress'],
            'meta': ['generator: wordpress'],
        },
        'Drupal': {
            'headers': ['x-drupal-cache', 'x-generator: drupal'],
            'body': ['drupal', '/sites/default/'],
            'meta': ['generator: drupal'],
        },
        'Joomla': {
            'headers': ['x-joomla-options'],
            'body': ['/joomla/', '/components/com_', '/media/jui/'],
            'meta': ['generator: joomla!'],
        },
        'DedeCMS': {
            'body': ['dedecms', '/plus/search.php', '/data/admin/'],
            'meta': ['generator: dedecms'],
        },
        'Discuz': {
            'body': ['discuz', 'forum.php', 'static/js/common.js'],
            'meta': ['generator: discuz!'],
        },
        'ThinkPHP': {
            'body': ['thinkphp', '?s=/', '__think__'],
        },
        'Laravel': {
            'headers': ['x-powered-by: laravel'],
            'body': ['laravel_session', '/storage/framework/'],
        },
        'Django': {
            'headers': ['x-framework: django'],
            'body': ['csrfmiddlewaretoken', 'django'],
            'cookie': ['csrftoken'],
        },
        'Spring Boot': {
            'headers': ['x-application-context'],
            'body': ['whitelabel error page', 'spring boot'],
        },
    }
    
    # Web服务器指纹规则
    SERVER_RULES = {
        'Nginx': ['server: nginx'],
        'Apache': ['server: apache'],
        'IIS': ['server: iis', 'microsoft-iis'],
        'Tomcat': ['server: apache-coyote', 'tomcat'],
        'LiteSpeed': ['server: litespeed'],
    }
    
    def __init__(self, url, timeout=10):
        """
        初始化指纹识别器
        
        参数:
            url: 目标URL (str)
            timeout: 请求超时秒数 (int)
        """
        self.url = url.rstrip('/')  # 移除末尾斜杠
        self.timeout = timeout
        self.results = {
            'cms': [],          # 检测到的CMS
            'server': None,     # Web服务器
            'language': None,   # 编程语言
            'framework': [],    # 框架
            'sensitive_files': []  # 敏感文件
        }
        
        # ===== 反黑名单：状态变量 =====
        self._request_count = 0
        self._ban_detected = False
        self._cooldown_until = 0
        self._lock = threading.Lock()
        self._last_request_time = 0
        self._min_interval = 1.0       # 指纹识别间隔稍长(秒)
        
    def _rotate_ua(self):
        """轮换User-Agent"""
        return random.choice(UA_POOL)
    
    def _random_delay(self):
        """随机延迟"""
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)
        return delay
    
    def _rate_limit(self):
        """请求频率控制"""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed + random.uniform(0, 0.5))
            self._last_request_time = time.time()
    
    def _check_ban(self, response):
        """检测是否被封禁"""
        if response is None:
            return False, ''
        if response.status_code in (403, 429, 503):
            content_lower = response.text[:2000].lower()
            for indicator in self.BAN_INDICATORS:
                if indicator.lower() in content_lower:
                    return True, f"状态码{response.status_code} + {indicator}"
            if len(response.text) < 100 and response.status_code in (429, 403):
                return True, f"HTTP {response.status_code}"
        return False, ''
    
    def _handle_ban(self, reason=''):
        """处理封禁：自动冷却"""
        import sys as _sys
        with self._lock:
            self._ban_detected = True
            cooldown = random.randint(15, 30)
            self._cooldown_until = time.time() + cooldown
        
        print(f"\n{Fore.RED}[!!!] 指纹检测: 检测到可能被限制!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    原因: {reason}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    冷却 {cooldown} 秒...{Style.RESET_ALL}\n")
        
        while time.time() < self._cooldown_until:
            remaining = int(self._cooldown_until - time.time())
            _sys.stdout.write(f"\r{Fore.CYAN}[冷却中] {remaining}秒...{Style.RESET_ALL}")
            _sys.stdout.flush()
            time.sleep(1)
        _sys.stdout.write(f"\r{' '*40}\r")
        print(f"{Fore.GREEN}[+] 冷却结束，继续{Style.RESET_ALL}\n")
        self._ban_detected = False
        
    def fetch_page(self):
        """
        获取目标页面信息（含反黑名单封装）
        
        返回:
            dict: 包含URL、状态码、响应头、响应体、Cookie等
                 失败时返回None
        """
        self._rate_limit()
        
        headers = {
            'User-Agent': self._rotate_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.9,en-US;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'max-age=0',
        }
        
        # 重试机制（最多3次）
        for attempt in range(3):
            try:
                if attempt > 0 or self._request_count > 0:
                    self._random_delay()
                
                response = requests.get(
                    self.url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                self._request_count += 1
                
                # 封禁检测
                is_banned, ban_reason = self._check_ban(response)
                if is_banned:
                    if attempt < 2:
                        self._handle_ban(ban_reason)
                        continue
                    else:
                        print(f"{Fore.YELLOW}[!] 持续受限，跳过页面获取{Style.RESET_ALL}")
                        return None
                
                return {
                    'url': response.url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text.lower(),
                    'cookies': dict(response.cookies),
                    'content_length': len(response.content),
                }
                
            except requests.exceptions.Timeout:
                if attempt < 2:
                    print(f"{Fore.YELLOW}[i] 超时，重试中... ({attempt+1}/3){Style.RESET_ALL}")
                    time.sleep(3)
                    continue
                print(f"{Fore.RED}[-] 请求超时 ({self.timeout}s){Style.RESET_ALL}")
                return None
            except requests.exceptions.ConnectionError:
                if attempt < 2:
                    print(f"{Fore.YELLOW}[i] 连接失败，重试中... ({attempt+1}/3){Style.RESET_ALL}")
                    time.sleep(5)
                    continue
                print(f"{Fore.RED}[-] 连接失败: 无法访问 {self.url}{Style.RESET_ALL}")
                return None
            except Exception as e:
                print(f"{Fore.RED}[-] 请求错误: {e}{Style.RESET_ALL}")
                return None
        
        return None
    
    def detect_cms(self, page_info):
        """
        检测CMS类型（内容管理系统）
        
        通过分析响应头、页面内容、Cookie来识别
        """
        if not page_info:
            return
        
        body = page_info['body']
        headers_str = str(page_info['headers']).lower()
        cookies_str = str(page_info['cookies']).lower()
        
        for cms_name, rules in self.CMS_RULES.items():
            match_count = 0
            
            # 检查响应头特征
            if 'headers' in rules:
                for pattern in rules['headers']:
                    if pattern.lower() in headers_str:
                        match_count += 1
            
            # 检查页面内容特征
            if 'body' in rules:
                for pattern in rules['body']:
                    if pattern.lower() in body:
                        match_count += 1
            
            # 检查Cookie特征
            if 'cookie' in rules:
                for pattern in rules['cookie']:
                    if pattern.lower() in cookies_str:
                        match_count += 1
            
            # 匹配度 >= 2 则判定为该CMS
            if match_count >= 2:
                self.results['cms'].append(cms_name)
                confidence = "高" if match_count >= 3 else "中"
                print(f"{Fore.GREEN}[+] 检测到CMS: {cms_name} (置信度: {confidence}){Style.RESET_ALL}")
    
    def detect_server(self, page_info):
        """
        检测Web服务器类型
        """
        if not page_info:
            return
        
        headers_str = str(page_info['headers']).lower()
        
        for server_name, patterns in self.SERVER_RULES.items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    self.results['server'] = server_name
                    print(f"{Fore.GREEN}[+] Web服务器: {server_name}{Style.RESET_ALL}")
                    return
    
    def detect_language(self, page_info):
        """
        检测后端编程语言
        主要通过 X-Powered-By 响应头判断
        """
        if not page_info:
            return
        
        headers = page_info.get('headers', {})
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'php' in powered_by:
            self.results['language'] = 'PHP'
            version = powered_by.split('/')[0] if '/' in powered_by else ''
            print(f"{Fore.GREEN}[+] 后端语言: PHP {version}{Style.RESET_ALL}")
        elif 'asp' in powered_by or '.net' in powered_by:
            self.results['language'] = 'ASP.NET'
            print(f"{Fore.GREEN}[+] 后端语言: ASP.NET{Style.RESET_ALL}")
        elif 'java' in powered_by or 'jsp' in powered_by:
            self.results['language'] = 'Java/JSP'
            print(f"{Fore.GREEN}[+] 后端语言: Java/JSP{Style.RESET_ALL}")
        elif 'python' in powered_by:
            self.results['language'] = 'Python'
            print(f"{Fore.GREEN}[+] 后端语言: Python{Style.RESET_ALL}")
    
    def check_sensitive_files(self):
        """
        检测敏感文件是否存在（含反黑名单机制）
        
        包括: Git泄露、SVN泄露、备份文件、配置文件等
        """
        sensitive_paths = [
            ('/.git/config', 'Git仓库泄露'),
            ('/.svn/entries', 'SVN版本控制泄露'),
            ('/.env', '环境变量文件泄露'),
            ('/.DS_Store', 'Mac系统文件泄露'),
            ('/WEB-INF/web.xml', 'Java Web配置泄露'),
            ('/robots.txt', 'Robots协议文件'),
            ('/sitemap.xml', '站点地图'),
            ('/crossdomain.xml', 'Flash跨域策略'),
            ('/phpinfo.php', 'PHP信息泄露'),
            ('/server-status', 'Apache状态页'),
            ('/actuator', 'Spring Boot监控端点'),
            ('/swagger-ui.html', 'Swagger API文档'),
            ('/druid/index.html', 'Druid数据库监控'),
            ('/admin/', '后台管理入口'),
            ('/wp-login.php', 'WordPress登录页'),
        ]
        
        print(f"\n{Fore.YELLOW}[*] 正在检测敏感文件... (含反封禁保护){Style.RESET_ALL}")
        
        found = []
        
        for path, description in sensitive_paths:
            # 反黑名单：频率控制 + 随机延迟
            self._rate_limit()
            self._random_delay()
            
            try:
                url = self.url + path
                resp = requests.get(
                    url,
                    headers={'User-Agent': self._rotate_ua()},
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                
                self._request_count += 1
                
                # 封禁检测
                is_banned, ban_reason = self._check_ban(resp)
                if is_banned:
                    self._handle_ban(ban_reason)
                    # 冷却后重试当前路径
                    try:
                        resp = requests.get(
                            url,
                            headers={'User-Agent': self._rotate_ua()},
                            timeout=5,
                            verify=False,
                            allow_redirects=False
                        )
                        self._request_count += 1
                    except:
                        continue
                
                # 状态码200且内容长度大于0
                if resp.status_code == 200 and len(resp.content) > 10:
                    print(f"{Fore.RED}[!] 发现: {path} -> {description}{Style.RESET_ALL}")
                    found.append({
                        'path': path,
                        'description': description,
                        'size': len(resp.content),
                        'status_code': resp.status_code
                    })
                    
            except:
                continue
        
        self.results['sensitive_files'] = found
        return found
    
    def run(self):
        """
        运行完整的指纹识别流程
        
        返回:
            dict: 识别结果
        """
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}[*] Web指纹识别工具 v1.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 目标: {self.url}{Style.RESET_ALL}")
        print(f"{'='*60}\n")
        
        # 第一步：获取页面
        print(f"{Fore.YELLOW}[1/4] 获取页面信息...{Style.RESET_ALL}")
        page_info = self.fetch_page()
        
        if page_info is None:
            print(f"\n{Fore.RED}[!] 无法获取页面，终止扫描{Style.RESET_ALL}")
            return self.results
        
        print(f"{Fore.GREEN}[+] 状态码: {page_info['status_code']}{Style.RESET_ALL}")
        print(f"[+] 页面大小: {page_info['content_length']} bytes")
        print(f"[+] 最终URL: {page_info['url']}")
        
        # 第二步：识别服务器
        print(f"\n{Fore.YELLOW}[2/4] 识别Web服务器...{Style.RESET_ALL}")
        self.detect_server(page_info)
        
        # 第三步：识别CMS和语言
        print(f"\n{Fore.YELLOW}[3/4] 识别应用技术栈...{Style.RESET_ALL}")
        self.detect_language(page_info)
        self.detect_cms(page_info)
        
        # 第四步：敏感文件检测
        print(f"\n{Fore.YELLOW}[4/4] 敏感文件检测...{Style.RESET_ALL}")
        self.check_sensitive_files()
        
        # 输出汇总
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}[!] 指纹识别完成!{Style.RESET_ALL}")
        print(f"{'='*60}")
        
        return self.results


def main():
    """主函数"""
    print(f"""
{Fore.MAGENTA}
╔══════════════════════════════════════════╗
║                                          ║
║        🔎 Web指纹识别工具 v1.0           ║        
║               Vlunter创建                ║                    
║        Web Fingerprint Scanner           ║
║                                          ║
╚══════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    url = input(f"{Fore.CYAN}[?] 请输入目标URL (例: http://example.com): {Style.RESET_ALL}").strip()
    
    if not url:
        print(f"{Fore.RED}[!] URL不能为空!{Style.RESET_ALL}")
        return
    
    # 自动补全协议
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 运行扫描
    scanner = FingerprintScanner(url)
    results = scanner.run()


if __name__ == '__main__':
    main()