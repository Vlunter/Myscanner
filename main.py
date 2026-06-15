# ```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主程序入口 - 安全扫描工具集
整合: 端口扫描 + 指纹识别 + 漏洞检测

用法:
    python main.py -t target.com -m all
    python main.py -t 192.168.1.1 -m port
    python main.py -t http://example.com -m vuln -o report.txt
"""

import sys
import argparse
import os
import time
import threading
from datetime import datetime
from colorama import Fore, Style, init

# 导入各扫描模块
try:
    from scanners.port_scanner import PortScanner
    from scanners.fingerprint import FingerprintScanner
    from scanners.vuln_scanner import VulnerabilityScanner
    from scanners.vuln_db import VulnDatabase, get_db
except ImportError as e:
    print(f"{Fore.RED}[!] 导入模块失败: {e}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 请确保: 1) 已激活虚拟环境  2) scanners目录存在{Style.RESET_ALL}")
    sys.exit(1)

# 初始化colorama
init(autoreset=True)

# ===== 全局变量：实时时间显示控制 =====
_time_display_running = False
_time_display_thread = None


def start_realtime_clock():
    """启动实时时钟显示线程（后台运行）"""
    global _time_display_running, _time_display_thread
    
    def _clock_worker():
        """时钟工作函数：每秒刷新显示当前时间"""
        global _time_display_running
        while _time_display_running:
            now = datetime.now()
            # 使用 \r 实现同行刷新，不换行
            sys.stdout.write(
                f"\r{Fore.GREEN}[时钟] {now.strftime('%Y-%m-%d %H:%M:%S')}"
                f"  |  运行时长: 计算中...{Style.RESET_ALL}    "
            )
            sys.stdout.flush()
            time.sleep(1)
    
    _time_display_running = True
    _time_display_thread = threading.Thread(target=_clock_worker, daemon=True)
    _time_display_thread.start()


def stop_realtime_clock(start_time=None):
    """停止实时时钟并显示最终信息"""
    global _time_display_running, _time_display_thread
    _time_display_running = False
    
    # 给线程一点时间结束
    if _time_display_thread and _time_display_thread.is_alive():
        time.sleep(0.3)
    
    # 清除时钟行并输出最终统计
    end_time = datetime.now()
    if start_time:
        duration = (end_time - start_time).total_seconds()
        sys.stdout.write(f"\r{' ' * 70}\r")  # 清除整行
        print(f"{Fore.GREEN}[+] 结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] 总耗时: {duration:.2f} 秒{Style.RESET_ALL}")
    else:
        sys.stdout.write(f"\r{' ' * 70}\r")


def banner():
    """显示程序Banner"""
    print(f"""
{Fore.MAGENTA}
╔═══════════════════════════════════════════════════╗
║                                                   ║
║     ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗   ██╗    ║
║     ╚══███╔╝██║   ██║██╔════╝██║  ██║██║   ██║    ║
║       ███╔╝ ██║   ██║█████╗  ███████║██║   ██║    ║
║      ███╔╝  ██║   ██║██╔══╝  ██╔══██║██║   ██║    ║
║     ███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝    ║ 
║     ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝     ║ 
║                                                   ║
║              安全扫描工具集 v1.0 Vlunter创建      ║
║              Security Scanner Toolkit             ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")


def run_port_scan(target, args):
    """运行端口扫描模块"""
    print(f"\n{Fore.CYAN}[>>> 启动端口扫描模块]{Style.RESET_ALL}\n")
    
    scanner = PortScanner(
        target=target,
        start_port=args.port_start,
        end_port=args.port_end,
        threads=args.threads
    )
    return scanner.run()


def run_fingerprint(target, args):
    """运行指纹识别模块"""
    print(f"\n{Fore.CYAN}[>>> 启动指纹识别模块]{Style.RESET_ALL}\n")
    
    url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
    scanner = FingerprintScanner(url, timeout=args.timeout)
    return scanner.run()


def run_vuln_scan(target, args):
    """运行漏洞扫描模块"""
    print(f"\n{Fore.CYAN}[>>> 启动漏洞扫描模块]{Style.RESET_ALL}\n")
    
    url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
    scanner = VulnerabilityScanner(url, timeout=args.timeout)
    vulns = scanner.run()
    
    if args.output:
        scanner.save_report(args.output)
    
    return vulns


def run_all(target, args):
    """运行全部扫描（完整模式）"""
    print(f"\n{Fore.YELLOW}[*** 全模式扫描 ***]{Style.RESET_ALL}")
    
    results = {}
    
    # 1. 端口扫描
    results['ports'] = run_port_scan(target, args)
    
    # 2. 指纹识别
    results['fingerprint'] = run_fingerprint(target, args)
    
    # 3. 漏洞扫描
    results['vulnerabilities'] = run_vuln_scan(target, args)
    
    return results


def run_db_mode():
    """
    漏洞库管理 / POC管理 / CVE查询 交互模式
    
    功能:
        1. 查看POC库统计和列表
        2. 添加自定义POC
        3. 删除自定义POC
        4. 搜索POC
        5. 在线CVE查询
        6. 导入/导出POC
    """
    print(f"\n{'='*60}")
    print(f"{Fore.MAGENTA}  漏洞数据库管理中心")
    print(f"{'='*60}")
    
    try:
        db = VulnDatabase()
    except Exception as e:
        print(f"{Fore.RED}[!] 数据库初始化失败: {e}{Style.RESET_ALL}")
        return None
    
    while True:
        print(f"\n{Fore.YELLOW}请选择操作:{Style.RESET_ALL}")
        print("    1. 库统计信息")
        print("    2. 列出所有POC (内置+自定义)")
        print("    3. 搜索POC (按关键词/CVE)")
        print("    4. 添加自定义POC")
        print("    5. 删除自定义POC")
        print("    6. 在线CVE查询")
        print("    7. 导出自定义POC")
        print("    8. 导入POC文件")
        print("    0. 返回主菜单")
        
        choice = input(f"\n{Fore.CYAN}[?] 选择操作 (0-8): {Style.RESET_ALL}").strip()
        
        if choice == '0':
            print(f"{Fore.CYAN}[*] 返回主菜单...{Style.RESET_ALL}\n")
            break
        
        elif choice == '1':
            # 统计信息
            db.get_stats()
        
        elif choice == '2':
            # 列出所有POC
            detail = input(f"{Fore.CYAN}[?] 显示详细信息? (y/n, 默认n): {Style.RESET_ALL}").strip().lower()
            db.list_all_pocs(show_details=(detail == 'y'))
        
        elif choice == '3':
            # 搜索POC
            keyword = input(f"{Fore.CYAN}[?] 输入搜索关键词: {Style.RESET_ALL}").strip()
            if keyword:
                db.search_poc(keyword)
            else:
                print(f"{Fore.YELLOW}[!] 请输入关键词{Style.RESET_ALL}")
        
        elif choice == '4':
            # 添加自定义POC
            print(f"\n{Fore.GREEN}[+] 添加自定义POC{Style.RESET_ALL}")
            poc = {}
            poc['name'] = input(f"  POC名称: ").strip()
            poc['description'] = input(f"  描述: ").strip()
            
            print(f"  类别: sqli/xss/lfi/rce/ssrf/unauth/info_leak/xxe/deser")
            poc['category'] = input(f"  类别 (如sqli): ").strip().lower()
            
            print(f"  严重度: Critical/High/Medium/Low")
            poc['severity'] = input(f"  严重度 (如High): ").strip().capitalize()
            
            poc['cve_id'] = input(f"  CVE编号 (可选，留空跳过): ").strip().upper()
            
            # Payloads
            payloads_str = input(f"  Payload列表 (逗号分隔，可选): ").strip()
            if payloads_str:
                poc['payloads'] = [p.strip() for p in payloads_str.split(',')]
            
            # Paths
            paths_str = input(f"  检测路径 (逗号分隔，可选): ").strip()
            if paths_str:
                poc['paths'] = [p.strip() for p in paths_str.split(',')]
            
            # Ports
            ports_str = input(f"  端口列表 (逗号分隔，可选): ").strip()
            if ports_str:
                try:
                    poc['ports'] = [int(p.strip()) for p in ports_str.split(',')]
                except ValueError:
                    poc['ports'] = []
            
            # Match patterns
            patterns_str = input(f"  匹配特征 (逗号分隔，可选): ").strip()
            if patterns_str:
                poc['match_patterns'] = [p.strip() for p in patterns_str.split(',')]
            
            # References
            refs_str = input(f"  参考链接 (逗号分隔，可选): ").strip()
            if refs_str:
                poc['references'] = [r.strip() for r in refs_str.split(',')]
            
            # Affected components
            comp_str = input(f"  影响组件 (逗号分隔，可选): ").strip()
            if comp_str:
                poc['affected_components'] = [c.strip() for c in comp_str.split(',')]
            
            if poc.get('name'):
                new_id = db.add_custom_poc(poc)
                print(f"{Fore.GREEN}[+] POC添加成功! ID: {new_id}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] 名称不能为空{Style.RESET_ALL}")
        
        elif choice == '5':
            # 删除自定义POC
            db.list_all_pocs(category=None)
            poc_id = input(f"\n{Fore.RED}[!] 输入要删除的POC ID: {Style.RESET_ALL}").strip()
            if poc_id:
                confirm = input(f"{Fore.RED}[!!] 确认删除? (y/n): {Style.RESET_ALL}").strip().lower()
                if confirm == 'y':
                    db.delete_custom_poc(poc_id)
                else:
                    print(f"{Fore.YELLOW}[!] 已取消删除{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] 请输入POC ID{Style.RESET_ALL}")
        
        elif choice == '6':
            # 在线CVE查询
            print(f"\n{Fore.LIGHTMAGENTA_EX}[*] 在线CVE/NVD查询{Style.RESET_ALL}")
            query_type = input(f"  查询方式: 1)CVE编号  2)关键词搜索: ").strip()
            
            if query_type == '1':
                cve_id = input(f"  输入CVE编号 (如 CVE-2021-44228): ").strip().upper()
                if cve_id:
                    db.query_cve_online(cve_id=cve_id, limit=5)
                else:
                    print(f"{Fore.YELLOW}[!] 请输入CVE编号{Style.RESET_ALL}")
            else:
                keyword = input(f"  输入关键词 (如 log4j struts spring): ").strip()
                if keyword:
                    limit_str = input(f"  返回数量 (默认10): ").strip()
                    limit = int(limit_str) if limit_str.isdigit() else 10
                    db.query_cve_online(keyword=keyword, limit=limit)
                else:
                    print(f"{Fore.YELLOW}[!] 请输入关键词{Style.RESET_ALL}")
        
        elif choice == '7':
            # 导出POC
            output_file = input(f"  导出路径 (回车使用默认): ").strip()
            exported = db.export_pocs(output_file if output_file else None)
            if not exported:
                print(f"{Fore.YELLOW}[!] 没有自定义POC可导出{Style.RESET_ALL}")
        
        elif choice == '8':
            # 导入POC
            import_file = input(f"  JSON文件路径: ").strip()
            if import_file and os.path.exists(import_file):
                count = db.import_pocs(import_file)
                print(f"{Fore.GREEN}[+] 导入完成: {count} 条POC{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] 文件不存在: {import_file}{Style.RESET_ALL}")
        
        else:
            print(f"{Fore.RED}[!] 无效选择{Style.RESET_ALL}")
    
    return None


def main():
    """
    主函数 - 解析命令行参数并执行对应功能
    
    支持两种运行方式:
      1. 命令行模式: python main.py -t target.com -m all
      2. 双击模式:   直接运行，进入交互式输入
    """
    # 创建命令行解析器
    parser = argparse.ArgumentParser(
        description='安全扫描工具集 - Security Scanner Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py -t 192.168.1.1 -m port              端口扫描
  python main.py -t http://example.com -m finger     指纹识别
  python main.py -t http://example.com -m vuln       漏洞扫描
  python main.py -t example.com -m all               全部扫描
  python main.py -t target.com -m all -o report.txt  保存报告
  
  或直接双击运行进入交互模式
        """
    )
    
    # 添加参数定义（target改为非必填，支持双击运行）
    parser.add_argument('-t', '--target',
                        help='目标IP地址、域名或URL (不填则进入交互模式)')
    parser.add_argument('-m', '--mode',
                        choices=['port', 'finger', 'vuln', 'all'],
                        default='all',
                        help='扫描模式: port/finger/vuln/all (默认: all)')
    parser.add_argument('--port-start', type=int, default=1,
                        help='起始端口号 (默认: 1)')
    parser.add_argument('--port-end', type=int, default=65535,
                        help='结束端口号 (默认: 65535)')
    parser.add_argument('--threads', type=int, default=100,
                        help='并发线程数 (默认: 100)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='请求超时时间(秒) (默认: 10)')
    parser.add_argument('-o', '--output',
                        help='输出报告文件名')
    
    # 解析参数
    args = parser.parse_args()
    
    # ===== 如果没有传入target参数，进入交互模式 =====
    if not args.target:
        # 检测是否为打包后的EXE运行（双击模式）
        is_exe = getattr(sys, 'frozen', False)

        banner()

        print(f"{Fore.YELLOW}[*] 欢迎使用安全扫描工具集{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[时钟] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

        # ===== 统一交互模式：EXE和Python脚本都进入交互输入 =====
        print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  交互式扫描模式{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}\n")

        # 交互式获取目标
        target = input(f"{Fore.CYAN}[?] 请输入扫描目标 (IP/域名/URL): {Style.RESET_ALL}").strip()
        if not target:
            print(f"{Fore.RED}[!] 未输入目标，程序退出{Style.RESET_ALL}")
            input("\n按回车键退出...")  # 防止闪退
            return
        args.target = target

        # 交互式选择模式
        print(f"\n{Fore.YELLOW}请选择扫描模式:{Style.RESET_ALL}")
        print("    1. 端口扫描 (port)")
        print("    2. Web指纹识别 (finger)")
        print("    3. 漏洞检测 (vuln)")
        print("    4. 全部扫描 (all) [推荐]")
        print("    5. 漏洞库管理 (db) [POC管理/CVE查询]")

        mode_choice = input(f"\n{Fore.CYAN}[?] 选择模式 (1-5，默认4): {Style.RESET_ALL}").strip()
        mode_map = {'1': 'port', '2': 'finger', '3': 'vuln', '4': 'all', '5': 'db', '': 'all'}
        args.mode = mode_map.get(mode_choice, 'all')

        print()
    
    # ===== 显示扫描配置信息 =====
    start_time = datetime.now()
    
    print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] 目标: {args.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] 模式: {args.mode}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] 开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}\n")
    
    # ===== 启动实时时钟显示 =====
    start_realtime_clock()
    
    try:
        # 根据模式调用对应的扫描函数
        mode_functions = {
            'port': run_port_scan,
            'finger': run_fingerprint,
            'vuln': run_vuln_scan,
            'all': run_all,
            'db': run_db_mode,
        }
        
        if args.mode == 'db':
            # 漏洞库模式不需要目标
            result = run_db_mode()
        else:
            result = mode_functions[args.mode](args.target, args)
    finally:
        # ===== 停止实时时钟并显示最终统计 =====
        stop_realtime_clock(start_time)
    
    print(f"\n{'='*65}")
    print(f"{Fore.GREEN}[+] 扫描完成!{Style.RESET_ALL}")
    print(f"{'='*65}")
    
    # ===== 防止EXE闪退：等待用户按回车 =====
    input("\n按回车键退出...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] 用户中断扫描 (Ctrl+C){Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!!!] 程序异常退出: {e}{Style.RESET_ALL}")
        sys.exit(1)