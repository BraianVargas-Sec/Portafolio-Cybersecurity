# CASE-002: Detección de Fuerza Bruta via WinRM

## Información General
| Campo | Detalle |
|---|---|
| Case ID | CASE-002 |
| Fecha | 2026-05-31 |
| Analista | Braian Vargas |
| Severidad | Alta (Level 10) |
| Estado | Cerrado |

## Descripción
Detección de ataque de fuerza bruta contra el servicio WinRM (puerto 5985) de una estación de trabajo Windows 10 desde un host no autorizado en la red interna.

## Indicadores de Compromiso (IOCs)
| Tipo | Valor |
|---|---|
| IP Origen | 192.168.100.20 (Kali Linux) |
| IP Destino | 192.168.100.30 (win10 - DESKTOP-BFU9I3D) |
| Puerto | 5985 (WinRM) |
| Protocolo | TCP/HTTP |
| Herramienta | Hydra v9.6 |
| Wordlist | rockyou.txt (14.3M passwords) |

## Evidencia
- **Wazuh Rule ID:** 100002 (regla personalizada)
- **Rule disparada por:** 92110 (WinRM activity) x10 en 60 segundos
- **Sysmon EventID:** 3 (Network Connection)
- **Timestamp:** 2026-05-31 13:51:54 UTC
- **Level:** 10

## Técnica MITRE ATT&CK
| Campo | Detalle |
|---|---|
| Técnica | T1110 - Brute Force |
| Táctica | Credential Access |
| Sub-técnica | T1110.001 - Password Guessing |
| Plataforma | Windows |

## Análisis
El host 192.168.100.20 (Kali Linux) ejecutó un ataque de fuerza bruta contra el puerto 5985 (WinRM) del host 192.168.100.30 (Windows 10) usando Hydra con la wordlist rockyou.txt. Wazuh detectó más de 10 conexiones WinRM en menos de 60 segundos desde la misma IP y disparó la regla personalizada 100002 clasificándolo como fuerza bruta nivel 10.

## Respuesta

### Contención
```powershell
# Bloquear IP atacante
New-NetFirewallRule -DisplayName "Block BruteForce Source" -Direction Inbound -RemoteAddress 192.168.100.20 -Action Block
# Deshabilitar WinRM si no es necesario
Disable-PSRemoting -Force
```

### Erradicación
- Verificar si hubo autenticación exitosa en el período del ataque
- Revisar logs de autenticación: `Get-EventLog -LogName Security -InstanceId 4624,4625`
- Cambiar contraseñas de cuentas expuestas

### Hardening
- Restringir WinRM a IPs administrativas autorizadas
- Implementar Account Lockout Policy (máx 5 intentos)
- Habilitar MFA para acceso remoto
- Cambiar puerto WinRM del default 5985

## Regla Personalizada Creada
```xml
<group name="winrm,brute_force,">
  <rule id="100002" level="10" frequency="10" timeframe="60">
    <if_matched_sid>92110</if_matched_sid>
    <description>Posible ataque de fuerza bruta via WinRM</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

## Lecciones Aprendidas
- WinRM sin restricción de IPs es vulnerable a ataques de fuerza bruta
- Las reglas de frecuencia en Wazuh permiten detectar patrones de ataque que reglas simples no detectan
- Account Lockout Policy es esencial para mitigar fuerza bruta
