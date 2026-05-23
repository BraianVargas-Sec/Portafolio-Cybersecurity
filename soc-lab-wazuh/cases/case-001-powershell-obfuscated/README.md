# Case 001 — PowerShell con EncodedCommand sospechoso

**Táctica MITRE:** Execution  
**Técnica:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Severidad:** Alta  
**Estado:** ✅ Documentado con alerta real  

---

## 1. Contexto

Los atacantes frecuentemente usan el parámetro `-EncodedCommand` de PowerShell para ofuscar comandos maliciosos en Base64. Esta técnica es usada por:

- Malware de primera etapa (droppers)
- Frameworks C2 como Metasploit, Cobalt Strike, Empire
- Scripts de persistencia
- Descarga de payloads en memoria

El objetivo es evadir soluciones de seguridad que analizan la línea de comandos en texto plano. Un analista SOC debe detectar esta actividad sin generar exceso de falsos positivos.

**¿Por qué es relevante?**
Según el reporte MITRE ATT&CK 2023, T1059.001 es la técnica de ejecución más utilizada en incidentes reales.

---

## 2. Reproducción en el laboratorio

> ⚠️ Solo ejecutar en entorno controlado y aislado.

### Simular el ataque (Kali Linux o Windows atacante)

```powershell
# Comando benigno codificado en Base64 para simular el patrón
$comando = "Write-Host 'simulacion de ataque'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($comando))

# Ejecutar como lo haría un atacante
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded
```

### Variantes más agresivas (para probar la regla)

```powershell
# Con bypass de execution policy
powershell.exe -ExecutionPolicy Bypass -EncodedCommand <base64>

# Ocultando la ventana
powershell.exe -WindowStyle Hidden -EncodedCommand <base64>

# Combinado (patrón alto riesgo)
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <base64>
```

---

## 3. Eventos de Windows y Sysmon generados

### Event ID 4688 — Creación de proceso (Windows Security)
```
Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Command Line:  powershell.exe -EncodedCommand <BASE64_STRING>
Creator Process: cmd.exe / explorer.exe
```

### Event ID 1 — Process Create (Sysmon)
```xml
<EventID>1</EventID>
<Image>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
<CommandLine>powershell.exe -NonInteractive -EncodedCommand JABX...</CommandLine>
<ParentImage>C:\Windows\System32\cmd.exe</ParentImage>
<User>DESKTOP-LAB\usuario</User>
<Hashes>SHA256=ABCD1234...</Hashes>
```

### Event ID 4103/4104 — PowerShell Script Block Logging
```
ScriptBlockText: Write-Host 'simulacion de ataque'
Path: (vacío — ejecutado desde memoria)
```

> **Nota:** Script Block Logging debe estar habilitado. Ver [docs/setup-sysmon.md](../../docs/setup-sysmon.md).

---

## 4. Regla de detección

### Sigma (fuente)

```yaml
# rules/sigma/encoded_commands.yml
title: PowerShell EncodedCommand Suspicious Usage
id: a2b4c6d8-1234-5678-abcd-ef0123456789
status: test
description: Detects PowerShell execution with encoded commands combined with evasion flags
author: briamrlz82
date: 2024/01/15
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-Enc '
            - '-EC '
    evasion_flags:
        CommandLine|contains:
            - '-NonInteractive'
            - '-WindowStyle Hidden'
            - '-ExecutionPolicy Bypass'
            - '-NoProfile'
    condition: selection and evasion_flags
falsepositives:
    - Software legítimo que use EncodedCommand (SCCM, scripts de administración)
    - Scripts de automatización internos
level: high
```

### Wazuh (implementación)

```xml
<!-- rules/wazuh/powershell_detection.xml -->
<group name="powershell,detection,execution">

  <!-- Regla base: PowerShell con EncodedCommand -->
  <rule id="100001" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-EncodedCommand|-Enc\s|-EC\s)</field>
    <description>PowerShell ejecutado con EncodedCommand - posible ofuscación</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>powershell_encoded</group>
  </rule>

  <!-- Regla de alto riesgo: EncodedCommand + flags de evasión -->
  <rule id="100002" level="14" frequency="1" timeframe="30">
    <if_sid>100001</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-NonInteractive|-WindowStyle\s+Hidden|-ExecutionPolicy\s+Bypass|-NoProfile)</field>
    <description>ALERTA ALTA: PowerShell con EncodedCommand y flags de evasión combinados</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
    <group>powershell_encoded,evasion,high_severity</group>
  </rule>

</group>
```

---

## 5. Alerta generada por Wazuh

```json
{
  "timestamp": "2024-01-15T14:32:07.412+0000",
  "rule": {
    "id": "100002",
    "level": 14,
    "description": "ALERTA ALTA: PowerShell con EncodedCommand y flags de evasión combinados",
    "groups": ["powershell_encoded", "evasion", "high_severity"],
    "mitre": {
      "technique": ["T1059.001", "T1027"],
      "tactic": ["Execution", "Defense Evasion"]
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
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABXAG...",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "user": "DESKTOP-LAB\\usuario",
        "processId": "4821"
      }
    }
  }
}
```

---

## 6. Falsos positivos identificados

| Fuente | Patrón | Acción |
|--------|--------|--------|
| SCCM / ConfigMgr | Usa `-EncodedCommand` para scripts de deploy | Excluir por `parentImage` = `ccmexec.exe` |
| Scripts admin internos | Pueden usar `-ExecutionPolicy Bypass` | Crear lista blanca por hash o ruta |
| Software de backup | Algunos usan PowerShell encoded | Excluir por usuario de servicio |

### Exclusión en Wazuh
```xml
<rule id="100003" level="0">
  <if_sid>100001</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)ccmexec\.exe$</field>
  <description>Excepción: PowerShell encoded desde SCCM (legítimo)</description>
</rule>
```

---

## 7. Mitigación

### Controles recomendados

| Control | Implementación | Prioridad |
|---------|---------------|-----------|
| Habilitar Script Block Logging | GPO: Computer Config → PowerShell | 🔴 Alta |
| Habilitar Transcription Logging | GPO + output a share centralizado | 🔴 Alta |
| Constrained Language Mode | AppLocker o WDAC | 🟡 Media |
| ASR Rule: Block PS from Office | Defender ATP Rule ID | 🟡 Media |
| AMSI | Activo por defecto en Win10+ | ✅ Verificar |

### GPO para habilitar logging
```
Computer Configuration > Administrative Templates >
Windows Components > Windows PowerShell

✅ Turn on Module Logging
✅ Turn on PowerShell Script Block Logging
✅ Turn on PowerShell Transcription
```

---

## 📎 Archivos del caso

- [`alert-sample.json`](./alert-sample.json) — Alerta real exportada de Wazuh
- [`../../rules/wazuh/powershell_detection.xml`](../../rules/wazuh/powershell_detection.xml) — Regla implementada
- [`../../rules/sigma/encoded_commands.yml`](../../rules/sigma/encoded_commands.yml) — Regla Sigma original

---

## 🔗 Referencias

- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [Atomic Red Team — T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/)
- [Microsoft — PowerShell Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
