# SysGuard 0.2

Segurança, diagnóstico e desempenho para Windows (complemento ao Windows Defender).
Interface escura com menu lateral. Abre sem janela de terminal.

## Páginas
- **Sistema:** Painel (CPU/GPU/RAM/rede em tempo real), Especificações (estilo CPU-Z/GPU-Z), Bateria (saúde real), Discos (SMART e espaço)
- **Desempenho:** Benchmark (CPU, RAM, disco, histórico e teste de estresse), Overlay (estilo MSI Afterburner), RGB e Ventoinhas
- **Segurança:** Hosts (backup, análise, restauração), Arquivos suspeitos, Integridade (SFC/DISM/CHKDSK)
- **Manutenção:** Desinstalador em lote, Limpeza (restos de programas), Registro

## Rodar
    pip install psutil
    python sysguard.py

Execute como administrador para alterar o hosts, rodar SFC/DISM e ler alguns sensores.

## Temperaturas, RGB e ventoinhas (opcional)
- **Temperaturas/RPM no Windows:** abra o [LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor) como administrador; o SysGuard lê os sensores dele. GPU NVIDIA funciona sem isso (via nvidia-smi).
- **RGB:** abra o [OpenRGB](https://openrgb.org) com o "SDK Server" ligado e `pip install openrgb-python`.
- **Controle de ventoinhas:** `pip install pythonnet` e coloque `LibreHardwareMonitorLib.dll` (+ `HidSharp.dll`) na pasta do SysGuard. Só funciona em PCs de mesa/placas que permitam controle por software; notebooks normalmente não permitem.

## Overlay
Atalho global **Ctrl+Shift+F10**. Mostra uso/temperatura de CPU e GPU, VRAM, RAM, rede, bateria. Não mostra FPS de jogos (isso exige injeção, como o RTSS). Use o jogo em "janela sem bordas".

## Gerar EXE
    build_exe.bat

Status: lógica e interface testadas no Linux; partes específicas do Windows (WMI, SMART, registro, sensores, hotkey) ainda precisam de teste em PC real.
