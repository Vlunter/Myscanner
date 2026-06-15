# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描报告生成器 - 支持HTML/JSON/TXT三种格式导出

功能:
    1. HTML报告: 带图表、颜色标记、统计面板，可直接在浏览器查看
    2. JSON报告: 结构化数据，方便二次处理/API对接
    3. TXT报告: 纯文本格式，终端友好
    
使用方法:
    from scanners.report_generator import ReportGenerator
    gen = ReportGenerator()
    gen.generate(scan_data, format='html', output='report.html')
"""

import os
import json
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# 报告输出目录
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')


class ReportGenerator:
    """
    扫描报告生成器
    
    支持格式:
        - html: 完整的HTML报告（含CSS样式、统计图表、漏洞详情）
        - json: 结构化JSON数据（方便程序处理）
        - txt: 纯文本格式（方便阅读和打印）
    """
    
    def __init__(self, output_dir=None):
        """
        初始化报告生成器
        
        参数:
            output_dir: 自定义输出目录 (可选)
        """
        self.output_dir = output_dir or REPORT_DIR
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 统计数据
        self.stats = {
            'total_targets': 0,
            'total_vulns': 0,
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'by_type': {},
            'scan_start': None,
            'scan_end': None,
            'duration': 0,
        }
    
    def generate(self, scan_data, format='html', output_file=None):
        """
        生成扫描报告
        
        参数:
            scan_data: dict, 扫描结果数据，应包含:
                {
                    'target': 目标地址,
                    'mode': 扫描模式,
                    'start_time': 开始时间,
                    'end_time': 结束时间,
                    'vulnerabilities': [漏洞列表],
                    'ports': [端口扫描结果],
                    'fingerprints': [指纹识别结果],
                    'security_headers': [安全头检测结果], (可选)
                    'db_matches': [漏洞库比对结果], (可选)
                }
                
            format: 输出格式 ('html' / 'json' / 'txt' / 'all')
            output_file: 自定义输出路径 (可选)
            
        返回:
            str: 生成的文件路径
        """
        # 更新统计数据
        self._update_stats(scan_data)
        
        if format == 'all':
            results = []
            for fmt in ['html', 'json', 'txt']:
                r = self._generate_by_format(scan_data, fmt, output_file)
                results.append(r)
            return results
        
        return self._generate_by_format(scan_data, format, output_file)
    
    def _generate_by_format(self, scan_data, format, output_file):
        """根据格式调用对应生成方法"""
        generators = {
            'html': self._generate_html,
            'json': self._generate_json,
            'txt': self._generate_txt,
        }
        
        generator = generators.get(format)
        if not generator:
            print(f"{Fore.RED}[!] 不支持的格式: {format}，支持: html/json/txt/all{Style.RESET_ALL}")
            return None
        
        return generator(scan_data, output_file)
    
    def _update_stats(self, data):
        """更新统计数据"""
        vulns = data.get('vulnerabilities', [])
        self.stats['total_targets'] += 1
        self.stats['total_vulns'] += len(vulns)
        self.stats['scan_start'] = data.get('start_time')
        self.stats['scan_end'] = data.get('end_time') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if data.get('start_time') and data.get('end_time'):
            try:
                t1 = datetime.strptime(data['start_time'], '%Y-%m-%d %H:%M:%S')
                t2 = datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S')
                self.stats['duration'] = str(t2 - t1)
            except:
                pass
        
        for v in vulns:
            sev = v.get('severity', 'Info')
            if sev not in self.stats['by_severity']:
                self.stats['by_severity'][sev] = 0
            self.stats['by_severity'][sev] += 1
            
            vtype = v.get('type', 'Unknown')
            self.stats['by_type'][vtype] = self.stats['by_type'].get(vtype, 0) + 1
    
    # ==================== HTML报告 ====================
    
    def _generate_html(self, data, output_file=None):
        """生成HTML格式的完整报告"""
        target = data.get('target', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output_file or os.path.join(
            self.output_dir, f'scan_report_{target.replace(":", "_").replace("/", "_")}_{timestamp}.html'
        )
        
        vulns = data.get('vulnerabilities', [])
        ports = data.get('ports', [])
        fingerprints = data.get('fingerprints', [])
        sec_headers = data.get('security_headers', [])
        db_matches = data.get('db_matches', [])
        
        # 严重程度颜色映射
        sev_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#20c997',
            'Info': '#6c757d'
        }
        
        # 构建漏洞详情表格行
        vuln_rows = ''
        for i, v in enumerate(vulns, 1):
            sev = v.get('severity', 'Info')
            color = sev_colors.get(sev, '#6c757d')
            evidence = v.get('evidence', 'N/A').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            url = v.get('url', '-').replace('<', '&lt;').replace('>', '&gt;')
            
            vuln_rows += f'''
            <tr>
                <td>{i}</td>
                <td><span class="badge badge-{sev.lower()}">{sev}</span></td>
                <td>{v.get('type', '-')}</td>
                <td style="max-width:300px;word-break:break-all">{url}</td>
                <td style="max-width:400px;word-break:break-all">{evidence}</td>
            </tr>'''
        
        if not vuln_rows:
            vuln_rows = '<tr><td colspan="5" class="text-center text-muted">未发现安全漏洞</td></tr>'
        
        # 端口扫描结果
        port_rows = ''
        for p in ports[:50]:  # 最多显示50个端口
            status_color = '#20c997' if p.get('status') == 'open' else '#6c757d'
            port_rows += f'''<tr>
                <td>{p.get('port', '-')}</td>
                <td style="color:{status_color}">{p.get('status', '-')}</td>
                <td>{p.get('service', '-')}</td>
            </tr>'''
        if not port_rows and ports:
            port_rows = '<tr><td colspan="3" class="text-center">无开放端口</td></tr>'
        elif not port_rows:
            port_rows = '<tr><td colspan="3" class="text-center text-muted">未执行端口扫描</td></tr>'
        
        # 指纹识别结果
        fp_items = ''
        for fp in fingerprints:
            fp_items += f'<div class="fp-item"><strong>{fp.get("type", "-")}:</strong> {fp.get("result", "-")}</div>'
        if not fp_items:
            fp_items = '<div class="text-muted">未执行指纹识别或无匹配结果</div>'
        
        # 安全头检测结果
        header_rows = ''
        for h in sec_headers:
            status_icon = '&#10004;' if h.get('secure') else '&#10008;'
            status_class = 'secure' if h.get('secure') else 'insecure'
            risk = h.get('risk', '')
            recommendation = h.get('recommendation', '')
            header_rows += f'''<tr>
                <td><code>{h.get("header", "-")}</code></td>
                <td class="{status_class}">{status_icon} {h.get("status", "-")}</td>
                <td>{risk}</td>
                <td style="font-size:12px">{recommendation}</td>
            </tr>'''
        if not header_rows:
            header_rows = '<tr><td colspan="4" class="text-center text-muted">未执行安全头检测</td></tr>'
        
        # 漏洞库比对结果
        match_items = ''
        for m in db_matches[:10]:
            poc = m.get('matched_poc', {}) if isinstance(m, dict) else {}
            mode_tag = '本地库' if m.get('match_mode') == 'local' else '在线CVE'
            score = m.get('match_score', 0)
            match_items += f'''<div class="db-match">
                <div class="match-header">
                    <span class="badge badge-info">{mode_tag}</span>
                    <span class="match-score">相似度: {score}分</span>
                </div>
                <div><strong>ID:</strong> {poc.get("id", "-")}</div>
                <div><strong>名称:</strong> {poc.get("name", "-")}</div>
                <div><strong>CVE:</strong> {poc.get("cve_id", "-") or "-"}</div>
                <div><strong>CVSS:</strong> {poc.get("cvss_score", "-")}</div>
                <div class="text-muted" style="font-size:12px">{poc.get("description", "")[:100]}</div>
            </div>'''
        if not match_items and db_matches:
            match_items = '<div class="text-muted">无匹配记录</div>'
        elif not match_items:
            match_items = '<div class="text-muted">未执行漏洞库比对</div>'
        
        # 统计图表数据
        chart_data_critical = self.stats['by_severity'].get('Critical', 0)
        chart_data_high = self.stats['by_severity'].get('High', 0)
        chart_data_medium = self.stats['by_severity'].get('Medium', 0)
        chart_data_low = self.stats['by_severity'].get('Low', 0)
        total_vulns = sum(self.stats['by_severity'].values())
        
        html_content = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Myscanner 扫描报告 - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* 头部 */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .header .meta {{ opacity: 0.85; font-size: 14px; }}
        .header .target-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.15);
            padding: 6px 16px;
            border-radius: 20px;
            font-family: monospace;
            font-size: 16px;
            margin-top: 10px;
        }}
        
        /* 统计卡片 */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: white;
            padding: 24px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-card .number {{ font-size: 36px; font-weight: 700; }}
        .stat-card .label {{ color: #666; font-size: 14px; margin-top: 4px; }}
        .stat-critical .number {{ color: #dc3545; }}
        .stat-high .number {{ color: #fd7e14; }}
        .stat-medium .number {{ color: #ffc107; }}
        .stat-low .number {{ color: #20c997; }}
        .stat-total .number {{ color: #4dabf7; }}
        
        /* 面板 */
        .panel {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .panel-header {{
            background: #f8f9fa;
            padding: 16px 24px;
            border-bottom: 1px solid #eee;
            font-weight: 600;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .panel-header .count {{
            background: #4dabf7;
            color: white;
            padding: 2px 12px;
            border-radius: 12px;
            font-size: 13px;
        }}
        .panel-body {{ padding: 20px 24px; }}
        
        /* 表格 */
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            color: #666;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #f1f3f5; font-size: 13px; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        
        /* 徽章 */
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #20c997; color: white; }}
        .badge-info {{ background: #4dabf7; color: white; }}
        
        /* 安全头状态 */
        .secure {{ color: #20c997; font-weight: 600; }}
        .insecure {{ color: #dc3545; font-weight: 600; }}
        
        /* 指纹项 */
        .fp-item {{
            background: #f8f9fa;
            padding: 8px 14px;
            border-radius: 6px;
            margin-bottom: 6px;
            font-size: 13px;
        }}
        
        /* 数据库匹配 */
        .db-match {{
            background: #f8f9fa;
            border-left: 3px solid #4dabf7;
            padding: 12px 16px;
            border-radius: 0 6px 6px 0;
            margin-bottom: 10px;
            font-size: 13px;
        }}
        .match-header {{ margin-bottom: 6px; }}
        .match-score {{ 
            float: right; 
            background: #e7f5ff; 
            color: #1971c2; 
            padding: 2px 10px; 
            border-radius: 10px; 
            font-size: 12px;
        }}
        
        /* 图表区域 */
        .chart-container {{
            display: flex;
            justify-content: center;
            align-items: flex-end;
            height: 180px;
            padding: 20px;
            gap: 30px;
        }}
        .chart-bar-wrapper {{ text-align: center; }}
        .chart-bar {{
            width: 60px;
            border-radius: 6px 6px 0 0;
            transition: height 0.5s ease;
            min-height: 4px;
        }}
        .bar-critical {{ background: #dc3545; }}
        .bar-high {{ background: #fd7e14; }}
        .bar-medium {{ background: #ffc107; }}
        .bar-low {{ background: #20c997; }}
        .chart-label {{ margin-top: 8px; font-size: 12px; color: #666; font-weight: 600; }}
        .chart-value {{ font-size: 18px; font-weight: 700; margin-top: 4px; }}
        
        /* 页脚 */
        .footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 13px;
        }}
        .footer a {{ color: #4dabf7; text-decoration: none; }}
        
        /* 无数据提示 */
        .text-center {{ text-align: center; }}
        .text-muted {{ color: #adb5bd; }}
        code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
<div class="container">
    <!-- 头部 -->
    <div class="header">
        <h1>&#128737; Myscanner 安全扫描报告</h1>
        <div class="meta">Myscanner Security Scanner v1.0 | 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div class="target-badge">&#127760; 目标: {target}</div>
        <div class="meta" style="margin-top:8px">
            扫描模式: {data.get('mode', '-')} | 耗时: {self.stats.get('duration', '-')}
        </div>
    </div>
    
    <!-- 统计概览 -->
    <div class="stats-grid">
        <div class="stat-card stat-total">
            <div class="number">{total_vulns}</div>
            <div class="label">总问题数</div>
        </div>
        <div class="stat-card stat-critical">
            <div class="number">{chart_data_critical}</div>
            <div class="label">&#128308; 严重 (Critical)</div>
        </div>
        <div class="stat-card stat-high">
            <div class="number">{chart_data_high}</div>
            <div class="label">&#128992; 高危 (High)</div>
        </div>
        <div class="stat-card stat-medium">
            <div class="number">{chart_data_medium}</div>
            <div class="label">&#128993; 中危 (Medium)</div>
        </div>
        <div class="stat-card stat-low">
            <div class="number">{chart_data_low}</div>
            <div class="label">&#128994; 低危 (Low)</div>
        </div>
    </div>
    
    <!-- 严重度分布图 -->
    <div class="panel">
        <div class="panel-header">
            &#128202; 严重度分布
        </div>
        <div class="panel-body">
            <div class="chart-container">
                <div class="chart-bar-wrapper">
                    <div class="chart-value">{chart_data_critical}</div>
                    <div class="chart-bar bar-critical" style="height:{max(chart_data_critical * 4, 4)}px"></div>
                    <div class="chart-label">Critical</div>
                </div>
                <div class="chart-bar-wrapper">
                    <div class="chart-value">{chart_data_high}</div>
                    <div class="chart-bar bar-high" style="height:{max(chart_data_high * 4, 4)}px"></div>
                    <div class="chart-label">High</div>
                </div>
                <div class="chart-bar-wrapper">
                    <div class="chart-value">{chart_data_medium}</div>
                    <div class="chart-bar bar-medium" style="height:{max(chart_data_medium * 4, 4)}px"></div>
                    <div class="chart-label">Medium</div>
                </div>
                <div class="chart-bar-wrapper">
                    <div class="chart-value">{chart_data_low}</div>
                    <div class="chart-bar bar-low" style="height:{max(chart_data_low * 4, 4)}px"></div>
                    <div class="chart-label">Low</div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 漏洞详情 -->
    <div class="panel">
        <div class="panel-header">
            &#9888;&#65039; 漏洞详情
            <span class="count">{len(vulns)} 条</span>
        </div>
        <div class="panel-body" style="padding:0;overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th width="40">#</th>
                        <th width="90">严重度</th>
                        <th width="160">类型</th>
                        <th>URL / 目标</th>
                        <th>详情 / 证据</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- 端口扫描 -->
    <div class="panel">
        <div class="panel-header">
            &#128279; 端口扫描结果
            <span class="count">{len([p for p in ports if p.get('status')=='open')]} 个开放</span>
        </div>
        <div class="panel-body" style="padding:0;overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th width="80">端口</th>
                        <th width="80">状态</th>
                        <th>服务</th>
                    </tr>
                </thead>
                <tbody>
                    {port_rows}
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Web指纹识别 -->
    <div class="panel">
        <div class="panel-header">
            &#128270; Web指纹识别
            <span class="count">{len(fingerprints)} 条</span>
        </div>
        <div class="panel-body">
            {fp_items}
        </div>
    </div>
    
    <!-- HTTP安全头检测 -->
    <div class="panel">
        <div class="panel-header">
            &#128274; HTTP安全头检测
            <span class="count">{len(sec_headers)} 项</span>
        </div>
        <div class="panel-body" style="padding:0;overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th>安全头</th>
                        <th width="80">状态</th>
                        <th>风险</th>
                        <th>建议</th>
                    </tr>
                </thead>
                <tbody>
                    {header_rows}
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- 漏洞库比对结果 -->
    <div class="panel">
        <div class="panel-header">
            &#128269; 漏洞库比对结果
            <span class="count">{len(db_matches)} 条匹配</span>
        </div>
        <div class="panel-body">
            {match_items}
        </div>
    </div>
    
    <!-- 页脚 -->
    <div class="footer">
        <p>由 <a href="https://github.com/Vlunter/Myscanner">Myscanner</a> 自动生成 | 
           扫描时间: {self.stats.get('scan_start', '-')} ~ {self.stats.get('scan_end', '-')}</p>
        <p style="margin-top:4px;font-size:11px;color:#bbb">
            本报告仅供授权安全测试参考 | 请勿用于非法用途
        </p>
    </div>
</div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] HTML报告已生成: {filename}{Style.RESET_ALL}")
        return filename
    
    # ==================== JSON报告 ====================
    
    def _generate_json(self, data, output_file=None):
        """生成JSON结构化报告"""
        target = data.get('target', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output_file or os.path.join(
            self.output_dir, f'scan_report_{target.replace(":", "_").replace("/", "_")}_{timestamp}.json'
        )
        
        report = {
            'generator': 'Myscanner v1.0',
            'generated_at': datetime.now().isoformat(),
            'target': data.get('target'),
            'scan_mode': data.get('mode'),
            'scan_time': {
                'start': data.get('start_time'),
                'end': data.get('end_time'),
                'duration': self.stats.get('duration')
            },
            'summary': {
                'total_vulnerabilities': len(data.get('vulnerabilities', [])),
                'by_severity': self.stats['by_severity'],
                'by_type': self.stats['by_type'],
                'open_ports_count': len([p for p in data.get('ports', []) if p.get('status') == 'open']),
                'fingerprint_count': len(data.get('fingerprints', [])),
                'security_headers_missing': len([h for h in data.get('security_headers', []) if not h.get('secure')]),
                'db_match_count': len(data.get('db_matches', []))
            },
            'results': {
                'vulnerabilities': data.get('vulnerabilities', []),
                'ports': data.get('ports', []),
                'fingerprints': data.get('fingerprints', []),
                'security_headers': data.get('security_headers', []),
                'db_matches': data.get('db_matches', [])
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"{Fore.GREEN}[+] JSON报告已生成: {filename}{Style.RESET_ALL}")
        return filename
    
    # ==================== TXT报告 ====================
    
    def _generate_txt(self, data, output_file=None):
        """生成TXT纯文本报告"""
        target = data.get('target', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output_file or os.path.join(
            self.output_dir, f'scan_report_{target.replace(":", "_").replace("/", "_")}_{timestamp}.txt'
        )
        
        lines = []
        lines.append('=' * 70)
        lines.append('  Myscanner 安全扫描报告')
        lines.append('=' * 70)
        lines.append('')
        lines.append(f'  目标:       {data.get("target", "-")}')
        lines.append(f'  扫描模式:   {data.get("mode", "-")}')
        lines.append(f'  开始时间:   {data.get("start_time", "-")}')
        lines.append(f'  结束时间:   {data.get("end_time", "-")}')
        lines.append(f'  总耗时:     {self.stats.get("duration", "-")}')
        lines.append(f'  生成时间:   {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append('')
        lines.append('-' * 70)
        lines.append('  统计概览')
        lines.append('-' * 70)
        lines.append(f'  总问题数:   {len(data.get("vulnerabilities", []))}')
        for sev, count in self.stats['by_severity'].items():
            if count > 0:
                lines.append(f'  [{sev:>10s}] {count} 个')
        lines.append('')
        
        # 漏洞详情
        vulns = data.get('vulnerabilities', [])
        lines.append('-' * 70)
        lines.append(f'  漏洞详情 ({len(vulns)} 条)')
        lines.append('-' * 70)
        if vulns:
            for i, v in enumerate(vulns, 1):
                lines.append(f'')
                lines.append(f'  [{i}] {v.get("type", "-")} ({v.get("severity", "?")})')
                lines.append(f'      URL:   {v.get("url", "-")}')
                lines.append(f'      详情:  {v.get("evidence", "N/A")}')
        else:
            lines.append('')
            lines.append('  未发现安全漏洞')
        lines.append('')
        
        # 端口扫描
        ports = data.get('ports', [])
        open_ports = [p for p in ports if p.get('status') == 'open']
        lines.append('-' * 70)
        lines.append(f'  端口扫描 ({len(open_ports)} 个开放)')
        lines.append('-' * 70)
        if ports:
            for p in ports[:30]:
                marker = '[+]' if p.get('status') == 'open' else '[-]'
                lines.append(f'  {marker} 端口 {str(p.get("port","?")).rjust(5):>5s}/tcp  {p.get("service","-"):>15s}')
        else:
            lines.append('  未执行端口扫描')
        lines.append('')
        
        # 指纹识别
        fps = data.get('fingerprints', [])
        lines.append('-' * 70)
        lines.append(f'  Web指纹识别 ({len(fps)} 条)')
        lines.append('-' * 70)
        if fps:
            for fp in fps:
                lines.append(f'  [*] {fp.get("type", "-")}: {fp.get("result", "-")}')
        else:
            lines.append('  无匹配结果')
        lines.append('')
        
        # 安全头
        sec_h = data.get('security_headers', [])
        missing_sec = [h for h in sec_h if not h.get('secure')]
        lines.append('-' * 70)
        lines.append(f'  HTTP安全头检测 ({len(missing_sec)} 项缺失)')
        lines.append('-' * 70)
        if sec_h:
            for h in sec_h:
                status = 'OK' if h.get('secure') else 'MISSING'
                lines.append(f'  [{status:>7s}] {h.get("header", "-"):>35s} - {h.get("risk", "")}')
        else:
            lines.append('  未执行安全头检测')
        lines.append('')
        
        # 漏洞库比对
        matches = data.get('db_matches', [])
        lines.append('-' * 70)
        lines.append(f'  漏洞库比对 ({len(matches)} 条匹配)')
        lines.append('-' * 70)
        if matches:
            for i, m in enumerate(matches[:10], 1):
                poc = m.get('matched_poc', {}) if isinstance(m, dict) else {}
                mode = '本地' if m.get('match_mode') == 'local' else '在线'
                score = m.get('match_score', 0)
                lines.append(f'  [{i}] [{mode}] ({score}分) {poc.get("name", "-")} CVE:{poc.get("cve_id","-") or "-"}')
        else:
            lines.append('  无匹配记录')
        lines.append('')
        lines.append('=' * 70)
        lines.append('  报告结束 - 由 Myscanner 自动生成')
        lines.append('  https://github.com/Vlunter/Myscanner')
        lines.append('=' * 70)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"{Fore.GREEN}[+] TXT报告已生成: {filename}{Style.RESET_ALL}")
        return filename


# ==================== 快捷函数 ====================

def generate_report(scan_data, format='html', output_file=None):
    """
    快捷函数：生成扫描报告
    
    参数:
        scan_data: 扫描结果字典
        format: html/json/txt/all
        output_file: 输出路径
        
    返回:
        str or list: 生成的文件路径
    """
    gen = ReportGenerator()
    return gen.generate(scan_data, format=format, output_file=output_file)


if __name__ == '__main__':
    # 测试：生成示例报告
    test_data = {
        'target': 'example.com',
        'mode': 'all',
        'start_time': '2026-06-15 14:00:00',
        'end_time': '2026-06-15 14:05:30',
        'vulnerabilities': [
            {'type': 'SQL注入', 'severity': 'High', 'url': 'http://example.com/search?q=test', 'evidence': 'SQL syntax error near...'},
            {'type': 'XSS跨站脚本', 'severity': 'Medium', 'url': 'http://example.com/page?id=1', 'evidence': '<script>alert(1)</script> reflected'},
            {'type': '信息泄露', 'severity': 'Low', 'url': 'http://example.com/.env', 'evidence': 'DB_PASSWORD=secret123'},
        ],
        'ports': [
            {'port': 22, 'status': 'open', 'service': 'ssh'},
            {'port': 80, 'status': 'open', 'service': 'http'},
            {'port': 443, 'status': 'open', 'service': 'https'},
            {'port': 3306, 'status': 'closed', 'service': 'mysql'},
        ],
        'fingerprints': [
            {'type': 'Web服务器', 'result': 'Nginx 1.18.0'},
            {'type': '后端语言', 'result': 'PHP 7.4'},
            {'type': 'CMS', 'result': 'WordPress 5.8'},
        ],
        'security_headers': [
            {'header': 'X-Frame-Options', 'secure': False, 'risk': '点击劫持', 'recommendation': '添加 X-Frame-Options: DENY'},
            {'header': 'Content-Security-Policy', 'secure': False, 'risk': 'XSS防护缺失', 'recommendation': '添加 CSP 头'},
            {'header': 'Strict-Transport-Security', 'secure': True, 'risk': '', 'recommendation': ''},
            {'header': 'X-Content-Type-Options', 'secure': False, 'risk': 'MIME嗅探', 'recommendation': '添加 nosniff'},
        ],
        'db_matches': [
            {'match_mode': 'local', 'match_score': 70, 'matched_poc': {'id': 'POC-SQLI-001', 'name': 'MySQL报错注入', 'cve_id': '', 'cvss_score': '', 'description': '通过构造错误SQL语句...'}},
            {'match_mode': 'online', 'match_score': 45, 'matched_poc': {'id': '', 'name': 'WordPress SQLi', 'cve_id': 'CVE-2023-XXXX', 'cvss_score': 8.1, 'description': 'WordPress plugin SQL injection...'}},
        ]
    }
    
    print(Fore.CYAN + "\n[测试] 生成示例报告..." + Style.RESET_ALL)
    gen = ReportGenerator()
    gen.generate(test_data, format='all')
