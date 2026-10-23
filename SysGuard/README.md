# SysGuard

Utilitario de seguranca e diagnostico para Windows (complemento ao Windows Defender).

Abas: Hosts, Sistema, Disco, Integridade, Arquivos suspeitos, Limpeza, Registro.

## Rodar
    pip install psutil
    python sysguard.py

Execute como administrador para alterar o hosts e rodar SFC/DISM.

## Gerar EXE
    build_exe.bat

Status: v0.1 - logica testada no Linux; partes especificas do Windows ainda precisam de teste.
