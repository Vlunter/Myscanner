# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP安全头检测模块

检测项目 (共12项):
    1. X-Frame-Options          - 防止点击劫持
    2. Content-Security-Policy   - 防止XSS/数据注入
    3. Strict-Transport-Security - 强制HTTPS
    4. X-Content-Type-Options    - 防止MIME嗅探
    5. Referrer-Policy           - 控制Referer泄露
    6. Permissions-Policy        - 浏览器权限控制
    7. X-XSS-Protection          - XSS过滤器(旧版)
    8. Content-Type              - 正确的Content-Type
    9. Server                    - 服务器信息泄露
    10. X-Powered-By             - 技术栈信息泄露
    11. Cache-Control            - 缓存控制
    12. Access-Control-Allow-Origin - CORS配置

使用方法:
    from scanners.security_headers import SecurityHeaderScanner
    scanner = SecurityHeaderScanner("https://example.com")
    results = scanner.scan()
"""

import re
import time
import random
import requests
import urllib3
from colorama import Fore, Style, init

init(autoreset=True)

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SecurityHeaderScanner:
    """
    HTTP安全头检测器
    
    检测目标网站的HTTP响应头安全性配置，
    给出每项安全头的状态、风险等级和修复建议。
    """
    
    # 安全头检测规则定义
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'description': '防止网页被嵌入到iframe中，防御点击劫持攻击',
            'secure_values': ['DENY', 'SAMEORIGIN'],
            'risk_level': 'High',
            'risk_if_missing': '点击劫持(Clickjacking)攻击',
            'recommendation': '添加: X-Frame-Options: DENY 或 SAMEORIGIN',
            'cwe': 'CWE-1021',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
        },
        'Content-Security-Policy': {
            'description': '定义页面可加载的资源来源，防止XSS和数据注入攻击',
            'secure_values': [],  # 只要存在即视为基本安全（具体策略需进一步分析）
            'risk_level': 'Critical',
            'risk_if_missing': 'XSS跨站脚本攻击、数据注入、内联脚本执行',
            'recommendation': '添加: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
            'cwe': 'CWE-79',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy']
        },
        'Strict-Transport-Security': {
            'description': '强制浏览器使用HTTPS连接，防止协议降级攻击',
            'secure_values': [],  # 存在且max-age>=31536000为最佳
            'min_max_age': 31536000,  # 1年
            'risk_level': 'High',
            'risk_if_missing': 'SSL剥离攻击(Strip)、中间人攻击',
            'recommendation': '添加: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'cwe': 'CWE-319',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
        },
        'X-Content-Type-Options': {
            'description': '阻止浏览器对响应内容进行MIME类型嗅探',
            'secure_values': ['nosniff'],
            'risk_level': 'Medium',
            'risk_if_missing': 'MIME嗅探导致的内容类型混淆攻击',
            'recommendation': '添加: X-Content-Type-Options: nosniff',
            'cwe': 'CWE-16',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
        },
        'Referrer-Policy': {
            'description': '控制HTTP Referer头信息的发送策略，防止敏感URL泄露',
            'secure_values': [
                'no-referrer', 'no-referrer-when-downgrade',
                'strict-origin', 'strict-origin-when-cross-origin',
                'origin', 'origin-when-cross-origin', 'same-origin'
            ],
            'risk_level': 'Low',
            'risk_if_missing': 'Referer信息泄露（可能包含敏感路径和参数）',
            'recommendation': '添加: Referrer-Policy: strict-origin-when-cross-origin',
            'cwe': 'CWE-200',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
        },
        'Permissions-Policy': {
            'description': '控制浏览器功能API的使用权限（摄像头、麦克风、地理位置等）',
            'secure_values': [],
            'risk_level': 'Low',
            'risk_if_missing': '恶意网站可能调用敏感设备API',
            'recommendation': '添加: Permissions-Policy: camera=(), microphone=(), geolocation=()',
            'cwe': 'CWE-200',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
        },
        'X-XSS-Protection': {
            'description': '启用浏览器内置的XSS过滤机制（已逐渐被CSP取代）',
            'secure_values': ['1', '1; mode=block'],
            'risk_level': 'Medium',
            'risk_if_missing': '旧版浏览器缺少XSS防护层',
            'recommendation': '添加: X-XSS-Protection: 1; mode=block （同时配合CSP使用）',
            'cwe': 'CWE-79',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection']
        },
        'Server': {
            'description': '服务器软件版本信息（应隐藏或最小化）',
            'secure_values': [],
            'is_info_leak': True,  # 信息泄露类检测
            'risk_level': 'Low',
            'risk_if_missing': '暴露服务器版本号，便于攻击者针对性利用已知漏洞',
            'recommendation': '修改配置隐藏或泛化版本号: Server: nginx (不显示版本)',
            'cwe': 'CWE-200',
            'references': []
        },
        'X-Powered-By': {
            'description': '后端技术栈信息标识（应完全移除）',
            'secure_values': [],
            'is_info_leak': True,
            'risk_level': 'Low',
            'risk_if_missing': '暴露技术栈细节（如PHP/ASP.NET/Express版本）',
            'recommendation': '移除此头或在服务器配置中禁用输出',
            'cwe': 'CWE-200',
            'references': []
        },
        'Cache-Control': {
            'description': '缓存控制策略（敏感页面应禁止缓存）',
            'secure_values': ['no-store', 'no-cache'],
            'risk_level': 'Medium',
            'risk_if_missing': '敏感页面可能被缓存到磁盘，导致信息泄露',
            'recommendation': '敏感页面添加: Cache-Control: no-store, no-cache, must-revalidate',
            'cwe': 'CWE-524',
            'references': []
        },
        'Access-Control-Allow-Origin': {
            'description': '跨域资源共享(CORS)配置',
            'secure_values': [],
            'risk_level': 'High',
            'risk_if_missing': '需根据业务需求评估；通配符*可能导致CSRF/CORS误配',
            'recommendation': '避免使用 * 通配符，指定明确允许的域名',
            'cwe': 'CWE-942',
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS']
        },
        # 额外检测项
        'Set-Cookie': {
            'description': 'Cookie安全属性检测（HttpOnly/Secure/SameSite）',
            'secure_values': [],
            'is_cookie_check': True,
            'risk_level': 'High',
            'risk_if_missing': 'Cookie可能被JS读取(HTTPOnly缺失)或明文传输(Secure缺失)',
            'recommendation': 'Cookie设置: HttpOnly; Secure; SameSite=Strict',
            'cwe': 'CWE-614 / CWE-319 / CWE-1004',
            'references': []
        }
    }
    
    def __init__(self, target, timeout=10):
        """
        初始化安全头扫描器
        
        参数:
            target: 目标URL (如 https://example.com)
            timeout: 请求超时时间(秒)
        """
        self.target = self._normalize_url(target)
        self.timeout = timeout
        self.results = []
        self.headers = {}
        
        # UA池（复用反封禁策略）
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
        ]
    
    @staticmethod
    def _normalize_url(url):
        """标准化URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def scan(self):
        """
        执行安全头检测
        
        返回:
            list: 检测结果列表，每个元素为dict:
                {
                    'header': 头名称,
                    'value': 实际值,
                    'secure': bool 是否安全,
                    'status': 状态描述,
                    'risk': 风险说明,
                    'recommendation': 修复建议,
                    'severity': 风险等级,
                    'cwe': CWE编号,
                }
        """
        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  HTTP安全头检测{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN}[*] 目标: {self.target}{Style.RESET_ALL}\n")
        
        try:
            # 发送请求获取响应头
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            resp = requests.get(
                self.target,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            self.headers = dict(resp.headers)
            
            print(f"{Fore.GREEN}[+] 成功获取响应 ({resp.status_code}){Style.RESET_ALL}")
            print(f"{'─'*55}\n")
            
            # 逐项检测
            for header_name, rule in self.SECURITY_HEADERS.items():
                result = self._check_header(header_name, rule)
                if result:
                    self.results.append(result)
                    self._print_result(result)
            
            # 输出汇总
            self._print_summary()
            
        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[!] 连接超时 ({self.timeout}s){Style.RESET_ALL}")
        except requests.exceptions.ConnectionError as e:
            print(f"{Fore.RED}[-] 连接失败: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] 检测出错: {e}{Style.RESET_ALL}")
        
        return self.results
    
    def _check_header(self, header_name, rule):
        """检查单个安全头"""
        actual_value = self.headers.get(header_name, '')
        
        is_cookie_check = rule.get('is_cookie_check', False)
        is_info_leak = rule.get('is_info_leak', False)
        
        if is_cookie_check:
            # Cookie特殊处理：检查Set-Cookie中的安全属性
            return self._check_cookies(rule)
        
        if is_info_leak:
            # 信息泄露类：有值反而不好
            if not actual_value:
                secure = True
                status = 'OK (未泄露)'
                risk = ''
                recommendation = ''
            else:
                secure = False
                status = f'LEAKED: {str(actual_value)[:50]}'
                risk = rule['risk_if_missing']
                recommendation = rule['recommendation']
        else:
            # 常规安全头：需要存在且值正确
            if not actual_value:
                secure = False
                status = 'MISSING'
                risk = rule['risk_if_missing']
                recommendation = rule['recommendation']
            else:
                # CSP和HTS特殊判断
                if header_name == 'Content-Security-Policy':
                    secure = True
                    status = f'PRESENT: {str(actual_value)[:60]}...'
                    risk = ''
                    recommendation = ''
                    
                    # 检查是否有不安全的策略
                    unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "data:"]
                    for pattern in unsafe_patterns:
                        if pattern.lower() in str(actual_value).lower():
                            status += ' [含不安全指令]'
                            risk = 'CSP中包含unsafe-inline/unsafe-eval，降低XSS防护效果'
                            recommendation = '移除unsafe-inline，改用nonce/hash方案'
                            break
                
                elif header_name == 'Strict-Transport-Security':
                    max_age_match = re.search(r'max-age\s*=\s*(\d+)', str(actual_value))
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        min_required = rule.get('min_max_age', 15768000)
                        if max_age >= min_required:
                            secure = True
                            status = f'OK (max-age={max_age}s)'
                            risk = ''
                            recommendation = ''
                        else:
                            secure = False
                            status = f'WEAK (max-age={max_age}s < {min_required}s)'
                            risk = 'HSTS max-age过短，建议至少设置为1年(31536000s)'
                            recommendation = rule['recommendation']
                    else:
                        secure = False
                        status = f'MALFORMED: {str(actual_value)[:40]}'
                        risk = 'HSTS格式错误'
                        recommendation = rule['recommendation']
                
                elif header_name == 'Access-Control-Allow-Origin':
                    val_str = str(actual_value).strip().lower()
                    if val_str == '*':
                        secure = False
                        status = f'RISKY: * (通配符)'
                        risk = 'CORS允许任意来源，可能导致数据窃取'
                        recommendation = rule['recommendation']
                    elif val_str.startswith('null'):
                        secure = False
                        status = f'RISKY: null'
                        risk = 'null origin可能被利用绕过CORS限制'
                        recommendation = rule['recommendation']
                    else:
                        secure = True
                        status = f'CONFIGURED: {str(actual_value)[:40]}'
                        risk = ''
                        recommendation = ''
                
                else:
                    # 标准值匹配
                    sec_vals = rule.get('secure_values', [])
                    if sec_vals:
                        value_upper = str(actual_value).strip().upper()
                        if any(v.upper() in value_upper for v in sec_vals):
                            secure = True
                            status = f'OK'
                            risk = ''
                            recommendation = ''
                        else:
                            secure = False
                            status = f'WEAK: {str(actual_value)[:40]}'
                            risk = f"值不符合推荐标准，建议设为: {' 或 '.join(sec_vals)}"
                            recommendation = rule['recommendation']
                    else:
                        # 只要有值就算通过
                        secure = True
                        status = f'PRESENT: {str(actual_value)[:50]}'
                        risk = ''
                        recommendation = ''
        
        severity_map = {
            'Critical': ('严重', Fore.RED),
            'High': ('高危', Fore.LIGHTRED_EX),
            'Medium': ('中危', Fore.YELLOW),
            'Low': ('低危', Fore.GREEN),
        }
        
        sev_label, sev_color = severity_map.get(rule.get('risk_level', 'Medium'), ('中危', Fore.YELLOW))
        
        return {
            'header': header_name,
            'value': str(actual_value) if actual_value else '',
            'secure': secure,
            'status': status,
            'risk': risk,
            'recommendation': recommendation,
            'severity': sev_label,
            'severity_color_code': rule.get('risk_level', 'Medium'),
            'cwe': rule.get('cwe', ''),
            'description': rule.get('description', ''),
            'references': rule.get('references', []),
        }
    
    def _check_cookies(self, rule):
        """检测Cookie的安全属性"""
        set_cookies = self.headers.get('Set-Cookie', '')
        
        if isinstance(set_cookies, list):
            cookies_list = set_cookies
        else:
            cookies_list = [set_cookies] if set_cookies else []
        
        if not cookies_list:
            return {
                'header': 'Cookie-Security',
                'value': '',
                'secure': None,
                'status': 'NO COOKIES',
                'risk': '',
                'recommendation': '',
                'severity': '-',
                'severity_color_code': 'Info',
                'cwe': '',
                'description': '未检测到Set-Cookie头',
                'references': [],
            }
        
        issues = []
        all_secure = True
        
        for cookie in cookies_list:
            cookie_lower = cookie.lower()
            
            if 'httponly' not in cookie_lower:
                issues.append('缺少HttpOnly属性')
                all_secure = False
            
            if 'secure' not in cookie_lower:
                issues.append('缺少Secure属性')
                all_secure = False
            
            if 'samesite' not in cookie_lower:
                issues.append('缺少SameSite属性')
                all_secure = False
        
        if all_secure and cookies_list:
            secure = True
            status = 'ALL SECURE'
            risk = ''
            recommendation = ''
        else:
            secure = False
            status = f'ISSUES: {" | ".join(set(issues))}'
            risk = rule['risk_if_missing']
            recommendation = rule['recommendation']
        
        return {
            'header': 'Cookie-Security',
            'value': f'{len(cookies_list)}个Cookie',
            'secure': secure,
            'status': status,
            'risk': risk,
            'recommendation': recommendation,
            'severity': rule.get('risk_level', 'High'),
            'severity_color_code': rule.get('risk_level', 'High'),
            'cwe': rule.get('cwe', ''),
            'description': rule.get('description', ''),
            'references': rule.get('references', []),
        }
    
    def _print_result(self, result):
        """打印单条检测结果"""
        if result['secure'] is None:
            icon = Fore.CYAN + '[*]' + Style.RESET_ALL
        elif result['secure']:
            icon = Fore.GREEN + '[+]' + Style.RESET_ALL
        else:
            icon = Fore.RED + '[!]' + Style.RESET_ALL
        
        sev_colors = {
            'Critical': Fore.RED, 'High': Fore.LIGHTRED_EX,
            'Medium': Fore.YELLOW, 'Low': Fore.GREEN, '-': Fore.WHITE
        }
        sev_color = sev_colors.get(result.get('severity_color_code', ''), Fore.WHITE)
        
        print(f"  {icon} {result['header']:<30s} "
              f"{sev_color}{result['severity']:<6s}{Style.RESET_ALL} "
              f"| {result['status']}")
        
        if result.get('risk'):
            print(f"      {Fore.YELLOW}风险: {result['risk']}{Style.RESET_ALL}")
        if result.get('recommendation'):
            print(f"      {Fore.CYAN}建议: {result['recommendation']}{Style.RESET_ALL}")
        print()
    
    def _print_summary(self):
        """打印检测结果汇总"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.get('secure') is True)
        failed = sum(1 for r in self.results if r.get('secure') is False)
        skipped = sum(1 for r in self.results if r.get('secure') is None)
        
        score = (passed / total * 100) if total > 0 else 0
        
        print(f"{'─'*55}")
        print(f"  {Fore.CYAN}检测结果汇总:{Style.RESET_ALL}")
        print(f"    总计检测: {total} 项")
        print(f"    {Fore.GREEN}通过: {passed} 项{Style.RESET_ALL}")
        print(f"    {Fore.RED}问题: {failed} 项{Style.RESET_ALL}")
        if skipped:
            print(f"    {Fore.CYAN}跳过: {skipped} 项{Style.RESET_ALL}")
        
        # 安全评分
        if score >= 80:
            score_color = Fore.GREEN
            grade = 'A'
        elif score >= 60:
            score_color = Fore.YELLOW
            grade = 'B'
        elif score >= 40:
            score_color = Fore.LIGHTRED_EX
            grade = 'C'
        else:
            score_color = Fore.RED
            grade = 'D'
        
        print(f"\n  安全评分: {score_color}{score:.1f}/100 (等级: {grade}){Style.RESET_ALL}")
        
        if failed > 0:
            print(f"\n  {Fore.YELLOW}[!] 建议优先修复以下问题:{Style.RESET_ALL}")
            critical_high = [r for r in self.results 
                           if not r.get('secure') and r.get('severity_color_code') in ('Critical', 'High')]
            for r in critical_high[:5]:
                print(f"    - {r['header']}: {r['risk'][:40]}")
        
        print()


if __name__ == '__main__':
    target = input("输入目标URL: ").strip() or "http://scanme.nmap.org"
    scanner = SecurityHeaderScanner(target)
    results = scanner.scan()
