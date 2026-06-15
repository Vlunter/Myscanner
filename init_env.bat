```batch
@echo off
chcp 65001 >nul
echo ============================================
echo   漏洞扫描器 - 环境初始化脚本
echo ============================================.

:: 创建目录
echo [*] 创建目录结构...
mkdir core logs output payloads scanners 2>nul

:: 创建虚拟环境
if not exist "venv" (
    echo [*] 创建虚拟环境...
    python -m venv venv
) else (
    echo [!] 虚拟环境已存在
)

:: 激活并安装依赖
echo [*] 激活虚拟环境...
call venv\Scripts\activate.bat

echo [*] 安装依赖包...
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

echo.
echo ============================================
echo   初始化完成！
echo ============================================
echo.
echo 下一步：打开 main.py 开始编写代码
pause