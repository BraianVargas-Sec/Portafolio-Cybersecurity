# CASE-004: Detección de Credential Dumping con Mimikatz

## Información General
| Campo | Detalle |
|---|---|
| Case ID | CASE-004 |
| Fecha | 2026-05-31 |
| Analista | Braian Vargas |
| Severidad | Alta (Level 4) |
| Estado | Cerrado |

## Descripción
Detección de ejecución de Mimikatz para dumping de credenciales en memoria en una estación de trabajo Windows 10. El atacante obtuvo el hash NTLM de una cuenta de usuario activa.

## Indicadores de Compromiso (IOCs)
| Tipo | Valor |
|---|---|
| Host víctima | 192.168.100.30 (win10 - DESKTOP-BFU9I3D) |
| Archivo malicioso | C:\Windows\Temp\mimikatz.exe |
| Proceso padre | powershell.exe |
| Hash NTLM extraído | [HASH_REDACTED] |
| Usuario comprometido | usuario@ejemplo.com |
| Herramienta | Mimikatz v2.2.0 |

## Evidencia
- **Wazuh Rule ID:** 92066 — Binary in suspicious location
- **Sysmon EventID:** 1 (Process Create)
- **Timestamp:** 2026-05-31 14:39:54 UTC
- **Cadena de procesos:** powershell.exe → mimikatz.exe
- **Comandos ejecutados:** privilege::debug, sekurlsa::logonpasswords

## Técnica MITRE ATT&CK
| Campo | Detalle |
|---|---|
| Técnica | T1003.001 - LSASS Memory |
| Táctica | Credential Access |
| Técnica | T1059.001 - PowerShell |
| Táctica | Execution |

## Análisis
El atacante transfirió Mimikatz al directorio `C:\Windows\Temp` y lo ejecutó via PowerShell con privilegios de administrador. Mimikatz ejecutó `privilege::debug` para obtener el privilegio SeDebugPrivilege y `sekurlsa::logonpasswords` para extraer credenciales de la memoria LSASS. Se obtuvo el hash NTLM `[HASH_REDACTED]` del usuario `usuario@ejemplo.com`. Wazuh detectó la ejecución del binario desde una ubicación sospechosa.

## Respuesta

### Contención
```powershell
# Terminar proceso Mimikatz
Stop-Process -Name mimikatz -Force
# Eliminar binario
Remove-Item C:\Windows\Temp\mimikatz.exe -Force
# Invalidar credenciales comprometidas
net user briam /logonpasswordchg:yes
```

### Erradicación
```powershell
# Buscar otros binarios sospechosos en Temp
Get-ChildItem C:\Windows\Temp\ -Filter *.exe
# Revisar procesos activos sospechosos
Get-Process | Where-Object {$_.Path -like "*Temp*"}
```

### Hardening
- Habilitar Windows Defender con protección en tiempo real
- Implementar Credential Guard para proteger LSASS
- Habilitar PPL (Protected Process Light) para LSASS
- Implementar AppLocker para bloquear ejecución desde C:\Windows\Temp
- Rotar todas las contraseñas de cuentas expuestas
- Habilitar autenticación multifactor

## Lecciones Aprendidas
- Mimikatz es detectado por Sysmon cuando se ejecuta desde ubicaciones sospechosas
- El hash NTLM puede usarse para ataques Pass-the-Hash sin necesitar la contraseña en texto plano
- Credential Guard previene el acceso a credenciales en memoria LSASS
- Windows Defender debe mantenerse activo para bloquear herramientas conocidas como Mimikatz
