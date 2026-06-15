# Myscanner - 安全扫描工具集

一款集成 **端口扫描 + Web指纹识别 + 漏洞检测** 的综合性安全扫描工具，支持交互式界面运行，打包后可独立使用。

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-green.svg)
![License](https://img.shields.io/badge/License/MIT-yellow.svg)

---

## 功能特性

| 模块 | 功能说明 |
|------|----------|
| **端口扫描** | TCP全连接扫描，支持 1-65535 全端口范围，自动识别服务名称 |
| **Web指纹识别** | 识别 CMS(WordPress/Django/Spring Boot等9种) / Web服务器(Nginx/Apache/IIS等5种) / 后端语言 / 敏感文件(15种) |
| **漏洞检测** | SQL注入 / XSS / 目录遍历 / 未授权访问 / 信息泄露 / SSRF 共6类漏洞 |
| **反黑名单机制** | UA轮换 / 随机延迟 / 频率限制 / 封禁检测 / 指数退避重试 / 自动冷却 |
| **实时时钟** | 扫描过程中实时显示当前时间 |
| **交互式界面** | 双击EXE即可在当前页面输入IP/域名进行扫描 |

---

## 项目结构

```
my_scanner/
├── main.py                 # 主程序入口（含交互模式）
├── config.py               # 全局配置（UA池、端口映射、敏感路径字典）
├── requirements.txt        # Python依赖清单
├── Myscanner.spec          # PyInstaller打包配置
├── init_env.bat            # Windows环境初始化脚本
├── dist/
│   └── Myscanner.exe       # 打包后的可执行文件（单文件，可直接分发）
└── scanners/               # 扫描模块目录
    ├── __init__.py
    ├── port_scanner.py     # 端口扫描模块（多线程并发）
    ├── fingerprint.py      # Web指纹识别模块（含反封禁）
    └── vuln_scanner.py     # 漏洞检测模块（含反封禁）
```

---

## 环境准备

### 系统要求

- **操作系统**: Windows 7 / 10 / 11 (64位)
- **Python**: 3.8 或以上版本（[下载地址](https://www.python.org/downloads/)）
- **网络**: 需要能访问目标主机的网络环境

### 安装 Python

1. 前往 [python.org](https://www.python.org/downloads/) 下载 Python 3.8+
2. 安装时 **务必勾选** `Add Python to PATH`
3. 打开命令行验证安装：

```bash
python --version
# 应输出: Python 3.8.x 或更高版本
```

---

## 开发流程

### 方式一：使用初始化脚本（推荐）

双击运行 `init_env.bat`，自动完成以下全部步骤：
- 创建虚拟环境 `venv/`
- 安装所有依赖包
- 创建输出目录结构

```bash
# 手动执行方式
init_env.bat
```

### 方式二：手动安装

```bash
# 1. 克隆或下载项目到本地
cd my_scanner

# 2. 创建虚拟环境（隔离项目依赖）
python -m venv venv

# 3. 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. 安装依赖包
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 依赖清单 (`requirements.txt`)

| 包名 | 版本要求 | 用途 |
|------|---------|------|
| `requests` | >=2.28.0 | HTTP请求库（核心依赖） |
| `beautifulsoup4` | >=4.11.0 | HTML解析（预留扩展） |
| `colorama` | >=0.4.6 | 终端彩色输出 |
| `tqdm` | >=4.64.0 | 进度条显示（预留扩展） |
| `urllib3` | >=2.0.0 | HTTP连接池 |

> 国内用户建议使用清华镜像源加速安装。

---

## 使用步骤

### 方式一：直接运行 EXE（最简单）

无需任何环境，双击即可使用：

```
dist\Myscanner.exe
```

启动后进入交互界面，按提示输入目标：

```
=======================================================
  交互式扫描模式
=======================================================

[?] 请输入扫描目标 (IP/域名/URL): 192.168.1.1

请选择扫描模式:
    1. 端口扫描 (port)
    2. Web指纹识别 (finger)
    3. 漏洞检测 (vuln)
    4. 全部扫描 (all) [推荐]

[?] 选择模式 (1-4，默认4): 4
```

### 方式二：命令行参数模式

```bash
# 端口扫描
python main.py -t 192.168.1.1 -m port

# Web指纹识别
python main.py -t http://example.com -m finger

# 漏洞检测
python main.py -t http://example.com -m vuln

# 全部扫描（推荐）
python main.py -t example.com -m all

# 自定义端口范围 + 保存报告
python main.py -t target.com -m all --port-start 1 --port-end 65535 -o report.txt

# 高级参数
python main.py -t target.com -m all --threads 200 --timeout 15
```

### 可用参数

| 参数 | 缩写 | 默认值 | 说明 |
|------|------|--------|------|
| `--target` | `-t` | 无（进入交互模式） | 目标IP、域名或URL |
| `--mode` | `-m` | `all` | 扫描模式: `port` / `finger` / `vuln` / `all` |
| `--port-start` | | `1` | 起始端口号 |
| `--port-end` | | `65535` | 结束端口号（全端口） |
| `--threads` | | `100` | 并发线程数 |
| `--timeout` | | `10` | 请求超时时间(秒) |
| `--output` | `-o` | 无 | 输出报告文件名 |

---

## 反黑名单机制说明

当扫描目标具有 WAF、防火墙或频率限制时，本工具内置以下防护策略：

| 策略 | 说明 |
|------|------|
| **User-Agent 轮换** | 8种浏览器UA池，每次请求随机切换 |
| **随机延迟** | 每次请求间隔 0.3~2.0 秒随机值 |
| **频率限制** | 控制每秒请求数，避免触发阈值 |
| **封禁检测** | 自动识别 HTTP 403/429/503 及验证码/WAF/Cloudflare 等18种特征词 |
| **指数退避重试** | 遇超时/连接失败自动重试最多3次，等待时间递增 |
| **自动冷却** | 检测到封禁后暂停 10~30 秒倒计时后继续扫描 |

如频繁触发限制，建议降低线程数（`--threads 50`）或增大超时时间（`--timeout 20`）。

---

## 打包为独立EXE

如果需要重新生成EXE文件：

```bash
# 1. 确保已激活虚拟环境并安装依赖
venv\Scripts\activate
pip install pyinstaller

# 2. 使用spec文件打包（单文件模式）
pyinstaller Myscanner.spec --clean -y

# 3. 生成的EXE位于
dist\Myscanner.exe
```

---

## 输出示例

```
╔═══════════════════════════════════════════════════╗
║                                                   ║
║              安全扫描工具集                       ║
║              Security Scanner Toolkit             ║
║                                                   ║
╚═══════════════════════════════════════════════════╝

[*] 目标: scanme.nmap.org
[*] 模式: port
[*] 开始时间: 2026-06-15 14:30:00
[时钟] 2026-06-15 14:30:05

[+] 端口    80 开放 -> http
[+] 端口   443 开放 -> https
[+] 端口    22 开放 -> ssh

[!] 扫描完成! 发现 3 个开放端口
[+] 结束时间: 2026-06-15 14:32:15
[+] 总耗时: 135.42 秒
```

---

## 免责声明

- 本工具仅用于**授权的安全测试**和**网络安全研究**
- 使用者需自行承担法律责任，禁止用于非法用途
- 请勿对未经授权的目标进行扫描

---

## License

MIT License
