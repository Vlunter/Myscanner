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
from datetime import datetime
from colorama import Fore, Style, init

# 导入各扫描模块
try:
    from scanners.port_scanner import PortScanner
    from scanners.fingerprint import FingerprintScanner
    from scanners.vuln_scanner import VulnerabilityScanner
except ImportError as e:
    print(f"{Fore.RED}[!] 导入模块失败: {e}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 请确保: 1) 已激活虚拟环境  2) scanners目录存在{Style.RESET_ALL}")
    sys.exit(1)

# 初始化colorama
init(autoreset=True)


def banner():
    """显示程序Banner"""
    print(f"""
{Fore.MAGENTA}
╔═══════════════════════════════════════════════════╗
║                                                   ║
║     ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗   ██╗   ║
║     ╚══███╔╝██║   ██║██╔════╝██║  ██║██║   ██║   ║
║       ███╔╝ ██║   ██║█████╗  ███████║██║   ██║   ║
║      ███╔╝  ██║   ██║██╔══╝  ██╔══██║██║   ██║   ║
║     ███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝   ║
║     ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ║
║                                                   ║
║              安全扫描工具集 v1.0                   ║
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


def main():
    """
    主函数 - 解析命令行参数并执行对应功能
    
    支持的命令行参数:
        -t, --target      目标IP/域名/URL (必填)
        -m, --mode        扫描模式: port/finger/vuln/all
        --port-start      起始端口 (默认: 1)
        --port-end        结束端口 (默认: 1024)
        --threads         线程数 (默认: 100)
        --timeout         超时秒数 (默认: 10)
        -o, --output      输出报告文件名
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
        """
    )
    
    # 添加参数定义
    parser.add_argument('-t', '--target', required=True,
                        help='目标IP地址、域名或URL (必填)')
    parser.add_argument('-m', '--mode',
                        choices=['port', 'finger', 'vuln', 'all'],
                        default='all',
                        help='扫描模式: port=端口扫描 / finger=指纹识别 / vuln=漏洞扫描 / all=全部')
    parser.add_argument('--port-start', type=int, default=1,
                        help='起始端口号 (默认: 1)')
    parser.add_argument('--port-end', type=int, default=1024,
                        help='结束端口号 (默认: 1024)')
    parser.add_argument('--threads', type=int, default=100,
                        help='并发线程数 (默认: 100)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='请求超时时间(秒) (默认: 10)')
    parser.add_argument('-o', '--output',
                        help='输出报告文件名')
    
    # 解析参数
    args = parser.parse_args()
    
    # 显示Banner
    banner()
    
    # 记录开始时间
    start_time = datetime.now()
    
    # 打印配置信息
    print(f"{Fore.CYAN}[*] 目标: {args.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] 模式: {args.mode}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] 开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    # 根据模式调用对应的扫描函数
    mode_functions = {
        'port': run_port_scan,
        'finger': run_fingerprint,
        'vuln': run_vuln_scan,
        'all': run_all,
    }
    
    result = mode_functions[args.mode](args.target, args)
    
    # 计算并显示耗时
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n{'='*65}")
    print(f"{Fore.GREEN}[+] 总耗时: {duration:.2f} 秒{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] 扫描完成!{Style.RESET_ALL}")
    print(f"{'='*65}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] 用户中断扫描 (Ctrl+C){Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!!!] 程序异常退出: {e}{Style.RESET_ALL}")
        sys.exit(1)