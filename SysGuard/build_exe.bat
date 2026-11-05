@echo off
rem Gera dist\SysGuard.exe (sem janela de terminal, pede administrador ao abrir)
pip install pyinstaller psutil openrgb-python pythonnet
pyinstaller --onefile --windowed --uac-admin --name SysGuard --hidden-import openrgb --hidden-import clr sysguard.py
pause
