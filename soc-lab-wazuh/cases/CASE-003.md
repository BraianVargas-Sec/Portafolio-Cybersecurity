# CASE-003: Detección de Reverse Shell

## Información General
| Campo | Detalle |
|---|---|
| Case ID | CASE-003 |
| Fecha | 2026-05-31 |
| Analista | Braian Vargas |
| Severidad | Alta (Level 4) |
| Estado | Cerrado |

## Descripción
Detección de reverse shell ejecutada desde una estación de trabajo Windows 10 hacia un host atacante Kali Linux. El payload fue generado con msfvenom y ejecutado desde una ubicación sospechosa.

## Indicadores de Compromiso (IOCs)
| Tipo | Valor |
|---|---|
| IP Origen (víctima) | 192.168.100.30 (win10 - DESKTOP-BFU9I3D) |
| IP Destino (atacante) | 192.168.100.20 (Kali Linux) |
| Puerto | 4444 |
| Protocolo | TCP |
| Payload | windows/x64/shell_reverse_tcp |
| Herramienta | msfvenom + netcat |
| Archivo malicioso | C:\Windows\Temp\payload.exe |

## Evidencia
- **Wazuh Rule ID:** 92052 — cmd.exe iniciado por proceso anormal
- **Wazuh Rule ID:** 92031 — Discovery activity ejecutada
- **Sysmon EventID:** 1 (Process Create)
- **Timestamp:** 2026-05-31 14:19:22 UTC
- **Proceso padre:** powershell.exe → payload.exe → cmd.exe

## Técnica MITRE ATT&CK
| Campo | Detalle |
|---|---|
| Técnica | T1059.003 - Windows Command Shell |
| Táctica | Execution |
| Técnica | T1571 - Non-Standard Port |
| Táctica | Command and Control |
| Técnica | T1105 - Ingress Tool Transfer |
| Táctica | Command and Control |

## Análisis
El atacante desde 192.168.100.20 (Kali) generó un payload con msfvenom (`windows/x64/shell_reverse_tcp`) y lo transfirió al win10 via HTTP. Al ejecutar `payload.exe` desde `C:\Windows\Temp`, se estableció una conexión reversa al puerto 4444 del atacante. Sysmon detectó la cadena de procesos anómala: `powershell.exe → payload.exe → cmd.exe`. Wazuh alertó por proceso cmd iniciado desde ubicación sospechosa y actividad de discovery posterior.

## Respuesta

### Contención
```powershell
# Terminar proceso malicioso
Stop-Process -Name payload -Force
# Bloquear IP atacante
New-NetFirewallRule -DisplayName "Block C2" -Direction Outbound -RemoteAddress 192.168.100.20 -RemotePort 4444 -Action Block
```

### Erradicación
```powershell
# Eliminar payload
Remove-Item C:\Windows\Temp\payload.exe -Force
# Buscar persistencia
schtasks /query /fo LIST
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}
```

### Hardening
- Habilitar Windows Defender y mantenerlo activo
- Implementar AppLocker para bloquear ejecución desde C:\Windows\Temp
- Monitorear conexiones salientes a puertos no estándar
- Implementar EDR para detección de comportamiento

## Lecciones Aprendidas
- Sysmon detecta cadenas de procesos anómalas (parent-child process relationships)
- Ejecutables en C:\Windows\Temp son una señal de alerta inmediata
- Windows Defender debe mantenerse activo — fue necesario deshabilitarlo para ejecutar el payload
- El puerto 4444 es un indicador común de herramientas de C2
