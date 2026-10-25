# SysGuard

Utilitario de seguranca e diagnostico para Windows (complemento ao Windows Defender).

Abas: Hosts, Sistema, Disco, Integridade, Arquivos suspeitos, Desinstalador (em lote), Limpeza, Registro.

## Rodar
    pip install psutil
    python sysguard.py

O programa abre **sem janela de terminal** (se for aberto com python.exe, ele se reabre sozinho com pythonw.exe; no EXE o build usa --windowed). Erros aparecem em janela e no Registro.

Execute como administrador para alterar o hosts e rodar SFC/DISM.

## Gerar EXE
    build_exe.bat

Status: v0.1 - logica testada no Linux; partes especificas do Windows ainda precisam de teste.
