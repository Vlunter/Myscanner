#python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描模块 - 支持TCP全连接扫描
功能：探测目标主机开放的端口
作者：新手教程示例
"""

import socket
import threading
from queue import Queue
from datetime import datetime
from colorama import Fore, Style, init

# 初始化colorama（让Windows支持彩色输出）
init(autoreset=True)


class PortScanner:
    """
    端口扫描器类
    
    使用方法:
        scanner = PortScanner("192.168.1.1", 1, 1024, 100)
        open_ports = scanner.run()
    """
    
    def __init__(self, target, start_port=1, end_port=1024, threads=100):
        """
        初始化扫描器
        
        参数:
            target: 目标IP地址或域名 (str)
            start_port: 起始端口号 (int)
            end_port: 结束端口号 (int)
            threads: 并发线程数 (int)
        """
        self.target = target              # 目标地址
        self.start_port = start_port       # 起始端口
        self.end_port = end_port           # 结束端口
        self.threads = threads             # 线程数
        self.open_ports = []               # 存储开放的端口
        self.queue = Queue()               # 任务队列
        self.lock = threading.Lock()       # 线程锁（防止打印混乱）
        
    def scan_port(self, port):
        """
        扫描单个端口
        
        参数:
            port: 要扫描的端口号 (int)
        """
        try:
            # 创建TCP套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # 设置3秒超时
            
            # 尝试连接目标
            result = sock.connect_ex((self.target, port))
            
            # connect_ex返回0表示连接成功
            if result == 0:
                with self.lock:  # 加锁，防止多线程同时打印导致乱码
                    self.open_ports.append(port)
                    
                    # 获取服务名称
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = 'unknown'
                        
                    print(f"{Fore.GREEN}[+] 端口 {port:5d} 开放 -> {service}{Style.RESET_ALL}")
            
            # 关闭套接字（重要！不关闭会耗尽资源）
            sock.close()
            
        except socket.gaierror:
            # 域名解析失败
            print(f"{Fore.RED}[-] 错误: 无法解析域名 '{self.target}'{Style.RESET_ALL}")
        except Exception as e:
            # 其他异常静默处理
            pass
            
    def worker(self):
        """
        工作线程函数
        从队列中取出端口任务并扫描
        """
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()  # 标记任务完成
    
    def run(self):
        """
        运行端口扫描
        
        返回:
            list: 开放的端口列表
        """
        # 打印扫描信息
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}[*] 目标: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 端口范围: {self.start_port} - {self.end_port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 线程数: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] 开始时间: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
        print(f"{'='*60}\n")
        
        # 将所有端口加入队列
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)
        
        # 创建并启动工作线程
        thread_list = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True  # 设置为守护线程（主程序退出时自动结束）
            t.start()
            thread_list.append(t)
        
        # 等待队列中的所有任务完成
        self.queue.join()
        
        # 打印结果摘要
        end_time = datetime.now().strftime('%H:%M:%S')
        print(f"\n{'='*60}")
        print(f"{Fore.YELLOW}[!] 扫描完成! 发现 {len(self.open_ports)} 个开放端口{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] 结束时间: {end_time}{Style.RESET_ALL}")
        
        if self.open_ports:
            print(f"\n{Fore.GREEN}[+] 开放端口列表:{Style.RESET_ALL}")
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = 'unknown'
                print(f"    └─ {port:>5}/tcp  ({service})")
        
        print(f"{'='*60}\n")
        
        return self.open_ports


def main():
    """主函数 - 提供交互式命令行界面"""
    
    # 显示Banner
    print(f"""
{Fore.MAGENTA}
╔══════════════════════════════════════════╗
║                                          ║
║        🔍 简易端口扫描器 v1.0            ║
║        Simple Port Scanner               ║
║                                          ║
║        Vlunter创建(^_^)                  ║
║                                          ║
╚══════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    # 获取用户输入
    target = input(f"{Fore.CYAN}[?] 请输入目标IP或域名: {Style.RESET_ALL}").strip()
    
    if not target:
        print(f"\n{Fore.RED}[!] 错误: 目标不能为空!{Style.RESET_ALL}")
        return
    
    # 选择扫描模式
    print(f"\n{Fore.YELLOW}请选择扫描模式:{Style.RESET_ALL}")
    print("    1. 快速扫描 (常用端口 1-1024)")
    print("    2. 全端口扫描 (1-65535)")
    print("    3. 自定义范围")
    
    choice = input(f"\n{Fore.CYAN}[?] 输入选项 (1/2/3): {Style.RESET_ALL}").strip()
    
    # 根据选择配置参数
    if choice == '1':
        scanner = PortScanner(target, 1, 1024, 100)
    elif choice == '2':
        scanner = PortScanner(target, 1, 65535, 200)
    elif choice == '3':
        try:
            start = int(input("[?] 起始端口: ") or "1")
            end = int(input("[?] 结束端口: ") or "1024")
            threads = int(input("[?] 线程数 (推荐100): ") or "100")
            scanner = PortScanner(target, start, end, threads)
        except ValueError:
            print(f"{Fore.RED}[!] 错误: 请输入有效数字!{Style.RESET_ALL}")
            return
    else:
        print(f"{Fore.RED}[!] 错误: 无效选项!{Style.RESET_ALL}")
        return
    
    # 运行扫描
    open_ports = scanner.run()
    
    # 保存结果到文件
    if open_ports:
        from os.path import join
        filename = f"output\\port_{target.replace('.', '_')}_{datetime.now().strftime('%m%d_%H%M')}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"端口扫描报告\n")
            f.write(f"{'='*40}\n")
            f.write(f"目标: {target}\n")
            f.write(f"时间: {datetime.now()}\n")
            f.write(f"开放端口数: {len(open_ports)}\n\n")
            f.write("端口列表:\n")
            for port in sorted(open_ports):
                f.write(f"  - {port}\n")
        
        print(f"{Fore.GREEN}[+] 结果已保存: {filename}{Style.RESET_ALL}")


# 当直接运行此文件时执行main函数
if __name__ == '__main__':
    main()
