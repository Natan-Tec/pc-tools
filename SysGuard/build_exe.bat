@echo off
rem Gera dist\SysGuard.exe (pede administrador ao abrir)
pip install pyinstaller psutil
pyinstaller --onefile --windowed --uac-admin --name SysGuard sysguard.py
pause
