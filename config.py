# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全局配置文件 - 存放所有可配置项
"""

import random

# ===== 扫描设置 =====
TIMEOUT = 10                    # 请求超时时间（秒）
MAX_THREADS = 50                # 最大线程数
RETRY_COUNT = 3                 # 重试次数

# ===== User-Agent池（模拟不同浏览器）=====
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

def get_random_ua():
    """获取随机User-Agent"""
    return random.choice(USER_AGENTS)

# ===== 常见端口服务映射 =====
PORT_SERVICES = {
    21: 'FTP',       22: 'SSH',      23: 'Telnet',   25: 'SMTP',
    53: 'DNS',       80: 'HTTP',     110: 'POP3',    135: 'RPC',
    139: 'NetBIOS',  143: 'IMAP',    443: 'HTTPS',   445: 'SMB',
    993: 'IMAPS',    995: 'POP3S',   1433: 'MSSQL',  1521: 'Oracle',
    3306: 'MySQL',   3389: 'RDP',    5432: 'PostgreSQL',
    5900: 'VNC',     6379: 'Redis',  8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9200: 'Elasticsearch',
    27017: 'MongoDB',
}

# ===== 敏感路径字典（用于目录扫描）=====
SENSITIVE_PATHS = [
    '/admin', '/login', '/manage', '/console',
    '/backup', '/config', '/test', '/debug',
    '/phpinfo.php', '/info.php', '/server-status',
    '/.git/', '/.svn/', '/.env', '/.DS_Store',
    '/wp-admin/', '/wp-login.php',
    '/robots.txt', '/sitemap.xml',
    '/api/', '/swagger-ui.html', '/actuator/',
]

# ===== 输出设置 =====
OUTPUT_DIR = "output"            # 输出目录
LOG_DIR = "logs"                 # 日志目录
LOG_LEVEL = "INFO"               # 日志级别