# Case 004 — Lateral Movement con PsExec

**Táctica MITRE:** Lateral Movement  
**Técnica:** T1570 — Lateral Tool Transfer  
**Técnica adicional:** T1021.002 — Remote Services: SMB/Windows Admin Shares  
**Severidad:** Crítica  
**Estado:** ✅ Documentado con regla funcional  

---

## 1. Contexto

**PsExec** es una herramienta legítima de Sysinternals que permite ejecutar procesos en sistemas remotos. Los atacantes la reutilizan extensivamente para:

- **Moverse lateralmente** entre equipos de la red
- **Ejecutar comandos** en múltiples sistemas simultáneamente
- **Desplegar ransomware** a toda la organización desde un punto central
- **Escalar privilegios** usando credenciales robadas previamente

### ¿Por qué es crítico?

- Usado masivamente en ataques de **ransomware** (Ryuk, Conti, LockBit) para propagación
- Requiere credenciales válidas — indica que el atacante **ya comprometió una cuenta**
- Viaja por **SMB (puerto 445)** — tráfico que muchas organizaciones no monitorean bien
- Deja rastros muy específicos y detectables si sabés dónde mirar

### Cómo funciona PsExec

```
Atacante                          Víctima remota
────────                          ──────────────
1. Copia PSEXESVC.exe   ───────▶  C:\Windows\PSEXESVC.exe
   via SMB (Admin$)
2. Crea servicio        ───────▶  Servicio "PSEXESVC" creado
3. Ejecuta comando      ───────▶  Proceso remoto ejecutado
4. Devuelve output      ◀───────  Resultado del comando
```

---

## 2. Reproducción en el laboratorio

> ⚠️ Solo ejecutar en entorno controlado con dos VMs en red interna.

### Prerequisitos del lab
- VM1: Windows 10 (atacante) con credenciales admin de VM2
- VM2: Windows 10 (víctima) con compartido Admin$ habilitado
- Red interna entre ambas VMs

### Técnica 1: PsExec original (Sysinternals)

```cmd
# Desde la máquina atacante
PsExec.exe \\192.168.1.101 -u DOMINIO\admin -p Password123 cmd.exe

# Ejecutar comando específico de forma remota
PsExec.exe \\192.168.1.101 -u admin -p Password123 ipconfig

# Ejecutar como SYSTEM en el equipo remoto
PsExec.exe \\192.168.1.101 -u admin -p Password123 -s cmd.exe
```

### Técnica 2: Impacket psexec.py (desde Linux/Kali)

```bash
# Usando hash NTLM (Pass-the-Hash — no necesita contraseña en texto plano)
python3 psexec.py -hashes :a87f3a337d73085c45f9416be5787d86 admin@192.168.1.101

# Con contraseña
python3 psexec.py DOMINIO/admin:Password123@192.168.1.101
```

### Técnica 3: PsExec para despliegue masivo (simulación ransomware)

```cmd
# Iterar sobre lista de IPs — como haría un ransomware
for /f %i in (hosts.txt) do PsExec.exe \\%i -u admin -p Pass123 -d payload.exe
```

---

## 3. Eventos generados

### Event ID 7045 — Nuevo servicio instalado (Windows System)  ⭐ Clave

```
Service Name:    PSEXESVC
Service Type:    User Mode Service
Start Type:      Demand Start
Service Account: LocalSystem
Image Path:      %SystemRoot%\PSEXESVC.exe
```

### Event ID 7036 — Servicio iniciado/detenido

```
Service Name: PSEXESVC
The PSEXESVC service entered the running state.
```

### Event ID 5145 — Acceso a recurso compartido (Windows Security)

```
Share Name:     \\*\ADMIN$
Share Path:     C:\Windows
Relative Target: PSEXESVC.exe
Access:         WriteData (or AddFile)
Account Name:   admin
Source Address: 192.168.1.100
```

### Event ID 4697 — Servicio instalado en el sistema

```
Service Name:    PSEXESVC
Service File Name: C:\Windows\PSEXESVC.exe
Service Account: LocalSystem
```

### Event ID 1 — Process Create (Sysmon) en la víctima

```xml
<EventID>1</EventID>
<Image>C:\Windows\PSEXESVC.exe</Image>
<ParentImage>C:\Windows\System32\services.exe</ParentImage>
<User>NT AUTHORITY\SYSTEM</User>
<!-- El proceso hijo del servicio PSEXESVC -->
<Image>C:\Windows\System32\cmd.exe</Image>
<ParentImage>C:\Windows\PSEXESVC.exe</ParentImage>
```

### Event ID 3 — Network Connection (Sysmon) en el atacante

```xml
<EventID>3</EventID>
<Image>C:\Tools\PsExec.exe</Image>
<DestinationIp>192.168.1.101</DestinationIp>
<DestinationPort>445</DestinationPort>
<Protocol>tcp</Protocol>
```

---

## 4. Reglas de detección

### Sigma

```yaml
title: Lateral Movement - PsExec Execution Detected
id: d5e7f9a1-4567-8901-defa-123456789012
status: test
description: |
    Detecta uso de PsExec para movimiento lateral mediante la creación
    del servicio PSEXESVC o la copia del binario en Admin$.
    Indicador fuerte de movimiento lateral o despliegue de ransomware.
author: briamrlz82
date: 2024/02/01
references:
    - https://attack.mitre.org/techniques/T1570/
    - https://attack.mitre.org/techniques/T1021/002/
tags:
    - attack.lateral_movement
    - attack.t1570
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    # Detección 1: Servicio PSEXESVC creado
    selection_service:
        EventID: 7045
        ServiceName: 'PSEXESVC'
    # Detección 2: Proceso hijo de PSEXESVC
    selection_process:
        ParentImage|endswith: '\PSEXESVC.exe'
    # Detección 3: Binario PsExec ejecutándose
    selection_binary:
        Image|endswith: '\PsExec.exe'
        CommandLine|contains: '\\'
    condition: selection_service or selection_process or selection_binary
falsepositives:
    - Administradores de sistemas usando PsExec para tareas legítimas
    - Scripts de automatización IT que usen PsExec
    - Herramientas de gestión remota basadas en PsExec
level: high
```

### Wazuh (XML)

```xml
<group name="psexec,lateral_movement,detection,critical">

  <!-- Regla 1: Servicio PSEXESVC instalado (Event ID 7045) -->
  <rule id="100040" level="14">
    <if_group>windows_security</if_group>
    <id>7045</id>
    <field name="win.system.message" type="pcre2">(?i)PSEXESVC</field>
    <description>ALTA: Servicio PSEXESVC instalado — PsExec usado para ejecución remota</description>
    <mitre>
      <id>T1570</id>
      <id>T1021.002</id>
    </mitre>
    <group>psexec_service,lateral_movement</group>
  </rule>

  <!-- Regla 2: Proceso hijo de PSEXESVC (Sysmon Event ID 1) -->
  <rule id="100041" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)PSEXESVC\.exe$</field>
    <description>CRÍTICO: Proceso ejecutado como hijo de PSEXESVC — comando remoto activo</description>
    <mitre>
      <id>T1570</id>
    </mitre>
    <group>psexec_child_process,lateral_movement,critical</group>
  </rule>

  <!-- Regla 3: PsExec conectando a host remoto (Sysmon Event ID 3) -->
  <rule id="100042" level="13">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)PsExec(64)?\.exe$</field>
    <field name="win.eventdata.destinationPort">445</field>
    <description>ALTA: PsExec estableciendo conexión SMB a host remoto</description>
    <mitre>
      <id>T1570</id>
      <id>T1021.002</id>
    </mitre>
    <group>psexec_network,lateral_movement</group>
  </rule>

  <!-- Regla 4: Escritura en Admin$ (acceso a share administrativo) -->
  <rule id="100043" level="12">
    <if_group>windows_security</if_group>
    <id>5145</id>
    <field name="win.eventdata.shareName" type="pcre2">(?i)ADMIN\$</field>
    <field name="win.eventdata.relativetargetname" type="pcre2">(?i)PSEXESVC\.exe</field>
    <description>ALTA: Binario PSEXESVC copiado al share ADMIN$ — inicio de movimiento lateral</description>
    <mitre>
      <id>T1570</id>
    </mitre>
    <group>psexec_admin_share,lateral_movement</group>
  </rule>

  <!-- Correlación: servicio + proceso hijo = confirmado -->
  <rule id="100044" level="15" frequency="2" timeframe="120">
    <if_matched_sid>100040</if_matched_sid>
    <if_sid>100041</if_sid>
    <same_field>win.system.computer</same_field>
    <description>CRÍTICO CONFIRMADO: PsExec lateral movement — servicio creado y comando ejecutado</description>
    <mitre>
      <id>T1570</id>
    </mitre>
    <group>psexec_confirmed,critical,lateral_movement</group>
  </rule>

</group>
```

---

## 5. Alerta generada

```json
{
  "timestamp": "2024-02-01T03:22:45.119+0000",
  "rule": {
    "id": "100041",
    "level": 15,
    "description": "CRÍTICO: Proceso ejecutado como hijo de PSEXESVC — comando remoto activo",
    "groups": ["psexec_child_process", "lateral_movement", "critical"],
    "mitre": {
      "technique": ["T1570"],
      "tactic": ["Lateral Movement"]
    }
  },
  "agent": {
    "id": "002",
    "name": "DESKTOP-VICTIM",
    "ip": "192.168.1.101"
  },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "cmd.exe /c whoami && ipconfig",
        "parentImage": "C:\\Windows\\PSEXESVC.exe",
        "user": "NT AUTHORITY\\SYSTEM",
        "processId": "6240",
        "parentProcessId": "5880"
      }
    }
  }
}
```

---

## 6. Falsos positivos

| Fuente | Patrón | Acción |
|--------|--------|--------|
| Admins IT usando PsExec | Horario laboral, usuario conocido, destinos esperados | Whitelist por usuario + horario |
| Scripts de automatización | PsExec desde servidor de gestión conocido | Whitelist por IP origen |
| Herramientas RMM | Algunas usan PSEXESVC internamente | Verificar vendor, excluir por hash |

> **Regla de oro:** PsExec a las 3 AM desde un equipo de usuario final hacia múltiples hosts = ransomware en progreso. Contener inmediatamente.

---

## 7. Mitigación

| Control | Implementación | Prioridad |
|---------|---------------|-----------|
| Bloquear SMB lateral (puerto 445) | Firewall entre segmentos de red | 🔴 Alta |
| Deshabilitar Admin$ en endpoints | GPO: `AutoShareWks = 0` | 🔴 Alta |
| Privilegios mínimos | No usar cuentas domain admin en endpoints | 🔴 Alta |
| Segmentación de red | VLANs por rol — usuarios no acceden a servidores | 🔴 Alta |
| Monitoreo Event ID 7045 | Alertar sobre cualquier nuevo servicio | 🟡 Media |

### Bloquear Admin$ via GPO

```
Computer Configuration → Windows Settings → 
Security Settings → Registry

Key: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
Value: AutoShareWks
Type: REG_DWORD
Data: 0
```

### Regla de firewall para bloquear SMB lateral

```powershell
# Bloquear SMB saliente desde endpoints (no servidores)
New-NetFirewallRule -DisplayName "Block SMB Lateral" `
    -Direction Outbound `
    -Protocol TCP `
    -LocalPort 445 `
    -Action Block `
    -Profile Domain
```

---

## 8. Hunting queries

### Kibana — buscar PSEXESVC en toda la red
```
event.code: "7045" AND winlog.event_data.ServiceName: "PSEXESVC"
```

### Buscar procesos hijos de PSEXESVC
```
event.code: "1" AND process.parent.name: "PSEXESVC.exe"
```

### Detectar movimiento lateral masivo (múltiples destinos)
```
event.code: "3" AND process.name: "PsExec.exe" AND network.transport: "tcp" AND destination.port: 445
```

---

## 📎 Archivos relacionados

- [`../../rules/wazuh/lateral_movement.xml`](../../rules/wazuh/lateral_movement.xml) — Reglas Wazuh
- [`../../rules/sigma/psexec_lateral.yml`](../../rules/sigma/psexec_lateral.yml) — Regla Sigma

---

## 🔗 Referencias

- [MITRE T1570 — Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [MITRE T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Sysinternals PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Atomic Red Team — T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/)
- [Detecting PsExec — SANS](https://www.sans.org/blog/detecting-lateral-movement-psexec/)
