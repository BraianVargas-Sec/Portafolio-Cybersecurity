# CASE-005: Detección de Exfiltración de Datos

## Información General
| Campo | Detalle |
|---|---|
| Case ID | CASE-005 |
| Fecha | 2026-05-31 |
| Analista | Braian Vargas |
| Severidad | Alta (Level 7) |
| Estado | Cerrado |

## Descripción
Detección de exfiltración de datos confidenciales desde una estación de trabajo Windows 10 comprometida hacia un host atacante Kali Linux mediante una conexión TCP en puerto no estándar.

## Indicadores de Compromiso (IOCs)
| Tipo | Valor |
|---|---|
| Host víctima | 192.168.100.30 (win10 - DESKTOP-BFU9I3D) |
| Host atacante | 192.168.100.20 (Kali Linux) |
| Puerto C2 | 5555 (no estándar) |
| Protocolo | TCP |
| Archivo exfiltrado | C:\Users\briam\Documents\datos sensibles.txt |
| Método | PowerShell TcpClient |

## Evidencia
- **Wazuh Rule ID:** 533 (Kali) — Puerto 5555 abierto detectado
- **Sysmon EventID:** 3 (Network Connection)
- **Timestamp:** 2026-05-31 18:48:33 UTC
- **Técnica:** PowerShell TcpClient stream para transferencia de datos

## Técnica MITRE ATT&CK
| Campo | Detalle |
|---|---|
| Técnica | T1041 - Exfiltration Over C2 Channel |
| Táctica | Exfiltration |
| Técnica | T1059.001 - PowerShell |
| Táctica | Execution |
| Técnica | T1571 - Non-Standard Port |
| Táctica | Command and Control |

## Análisis
El atacante desde 192.168.100.20 (Kali) levantó un listener en el puerto 5555 usando netcat. Desde el win10 comprometido ejecutó un script PowerShell usando `System.Net.Sockets.TcpClient` para conectarse al puerto 5555 del atacante y transmitir el contenido del archivo `datos sensibles.txt`. Wazuh detectó la apertura del puerto 5555 en el host Kali (regla 533 - netstat change). La exfiltración se completó exitosamente — el archivo llegó al host atacante.

## Respuesta

### Contención
```powershell
# Bloquear conexiones salientes a puertos no estándar
New-NetFirewallRule -DisplayName "Block Non-Standard Ports" -Direction Outbound -RemotePort 4444,5555,1337,8888 -Action Block
# Aislar el host de la red
Disable-NetAdapter -Name "Ethernet 2"
```

### Erradicación
```powershell
# Revisar conexiones activas
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
# Buscar scripts PowerShell sospechosos
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Select-Object -First 20
```

### Hardening
- Implementar DLP (Data Loss Prevention) para detectar transferencias de datos sensibles
- Bloquear conexiones salientes a puertos no estándar via firewall
- Monitorear uso de PowerShell con ScriptBlock Logging habilitado
- Implementar segmentación de red para limitar comunicación entre hosts
- Alertar ante apertura de nuevos puertos en hosts de la red

## Lecciones Aprendidas
- PowerShell puede usarse para exfiltrar datos sin herramientas externas
- Wazuh detecta cambios en puertos abiertos via netstat (regla 533)
- Puertos no estándar como 5555 son indicadores de actividad C2
- DLP y monitoreo de PowerShell son controles esenciales para detectar exfiltración
