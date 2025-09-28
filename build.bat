@echo off
chcp 65001

echo 激活 conda 环境...
call conda.bat activate pyins

echo 使用 Nuitka 打包项目...
nuitka --onefile --windows-icon-from-ico=favicon.ico ./ssh2server.py

echo 打包完成。
pause