# CASE-001: Detección de Movimiento Lateral via WinRM

## Información General
| Campo | Detalle |
|---|---|
| Case ID | CASE-001 |
| Fecha | 2026-05-31 |
| Analista | Braian Vargas |
| Severidad | Media (Level 4) |
| Estado | Cerrado |

## Descripción
Detección de actividad WinRM sospechosa desde un host no autorizado hacia una estación de trabajo Windows 10 en la red interna.

## Indicadores de Compromiso (IOCs)
| Tipo | Valor |
|---|---|
| IP Origen | 192.168.100.20 (Kali Linux) |
| IP Destino | 192.168.100.30 (win10 - DESKTOP-BFU9I3D) |
| Puerto | 5985 (WinRM) |
| Protocolo | TCP |
| Proceso | System (PID 4) |

## Evidencia
- **Wazuh Rule ID:** 92110
- **Sysmon EventID:** 3 (Network Connection)
- **Timestamp:** 2026-05-31 16:23:27 UTC
- **Log:** Microsoft-Windows-Sysmon/Operational

## Técnica MITRE ATT&CK
| Campo | Detalle |
|---|---|
| Técnica | T1021.006 - Windows Remote Management |
| Táctica | Lateral Movement |
| Plataforma | Windows |

## Análisis
El host 192.168.100.20 (Kali Linux) inició una conexión TCP al puerto 5985 (WinRM) del host 192.168.100.30 (Windows 10). La conexión fue recibida por el proceso System del kernel de Windows. Wazuh detectó la actividad como movimiento lateral mediante Windows Remote Management.

## Respuesta

### Contención
```powershell
# Bloquear IP origen
New-NetFirewallRule -DisplayName "Block Unauthorized WinRM" -Direction Inbound -RemoteAddress 192.168.100.20 -Action Block
# Deshabilitar WinRM si no es necesario
Disable-PSRemoting -Force
```

### Erradicación
- Revisar tareas programadas: `schtasks /query /fo LIST`
- Revisar usuarios locales: `net user`
- Revisar servicios nuevos: `Get-Service | Where-Object {$_.StartType -eq 'Automatic'}`

### Hardening
- Restringir WinRM solo a IPs administrativas autorizadas
- Implementar autenticación con certificados en WinRM
- Crear regla de alerta nivel alto en Wazuh para WinRM desde IPs no autorizadas

## Lecciones Aprendidas
- WinRM expuesto en red interna sin restricción de IPs representa un vector de movimiento lateral
- Sysmon EventID 3 con la config adecuada detecta conexiones de red en tiempo real
- Wazuh mapea automáticamente la actividad a MITRE ATT&CK T1021.006
