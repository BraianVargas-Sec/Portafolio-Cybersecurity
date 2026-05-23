# 🟢 Windows Hardening — CIS Benchmark + Scripts PowerShell

> Hardening de sistemas Windows basado en CIS Benchmark v2.0, con scripts PowerShell automatizados, GPOs exportadas y documentación técnica por control.

[![CIS](https://img.shields.io/badge/Basado%20en-CIS%20Benchmark%20v2.0-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![PowerShell](https://img.shields.io/badge/PowerShell-Automatizado-0d1117?style=for-the-badge&logo=powershell&logoColor=00ff88)](.)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%20Server%202019%2F2022-0d1117?style=for-the-badge&logo=windows&logoColor=00ff88)](.)
[![Status](https://img.shields.io/badge/Status-Activo-00ff88?style=for-the-badge)](.)

---

## 🎯 Objetivo

Implementar y documentar controles de seguridad en sistemas Windows siguiendo el estándar **CIS Benchmark**, con foco en:

- Reducir la superficie de ataque del sistema operativo
- Fortalecer la autenticación y gestión de credenciales
- Habilitar logging y auditoría para visibilidad SOC
- Controlar la ejecución de código no autorizado

> Cada control está documentado con: qué protege, cómo aplicarlo, cómo verificarlo y qué impacto operativo tiene.

---

## 📂 Estructura

```
windows-hardening/
│
├── 📄 README.md                        ← Este archivo
├── 📂 scripts/
│   ├── apply-cis-baseline.ps1         ← Script principal — aplica todos los controles
│   ├── powershell-hardening.ps1       ← Logging y restricciones de PowerShell
│   ├── defender-hardening.ps1         ← Windows Defender + ASR Rules
│   ├── audit-policy.ps1               ← Política de auditoría completa
│   └── check-compliance.ps1           ← Verifica el estado actual del sistema
│
├── 📂 gpo/
│   └── security-baseline.md           ← GPOs documentadas por categoría
│
└── 📂 docs/
    ├── controles-cis.md               ← Controles implementados con justificación
    └── impacto-operativo.md           ← Qué puede romper y cómo manejarlo
```

---

## 🛡️ Controles implementados

### 🔐 Autenticación y contraseñas

| Control CIS | Configuración | Valor aplicado |
|-------------|--------------|----------------|
| 1.1.1 | Longitud mínima de contraseña | 14 caracteres |
| 1.1.2 | Complejidad de contraseña | Habilitada |
| 1.1.3 | Historial de contraseñas | 24 contraseñas |
| 1.1.4 | Edad máxima de contraseña | 60 días |
| 1.2.1 | Umbral de bloqueo de cuenta | 5 intentos |
| 1.2.2 | Duración del bloqueo | 15 minutos |

### 📋 Auditoría y logging

| Control | Configuración | Estado |
|---------|--------------|--------|
| Logon/Logoff | Éxito y fallo | ✅ |
| Account Logon | Éxito y fallo | ✅ |
| Object Access | Fallo | ✅ |
| Privilege Use | Fallo | ✅ |
| Process Creation | Éxito | ✅ |
| PowerShell Script Block | Habilitado | ✅ |
| PowerShell Transcription | Habilitado | ✅ |

### 🔒 Restricciones del sistema

| Control | Configuración | Estado |
|---------|--------------|--------|
| WDigest Auth | Deshabilitado | ✅ |
| LLMNR | Deshabilitado | ✅ |
| NetBIOS over TCP/IP | Deshabilitado | ✅ |
| SMBv1 | Deshabilitado | ✅ |
| RDP NLA | Habilitado | ✅ |
| UAC | Nivel máximo | ✅ |

### 🛡️ Windows Defender + ASR Rules

| ASR Rule | Descripción | Estado |
|----------|-------------|--------|
| Block Office macros from spawning processes | Previene macros maliciosas | ✅ |
| Block credential stealing from lsass.exe | Protege contra Mimikatz | ✅ |
| Block executable content from email | Previene phishing | ✅ |
| Block untrusted/unsigned processes from USB | Previene ejecución desde USB | ✅ |
| Block obfuscated script execution | Previene PS obfuscado | ✅ |

---

## 🚀 Uso rápido

```powershell
# 1. Verificar estado actual antes de aplicar
.\scripts\check-compliance.ps1

# 2. Aplicar baseline completo (requiere admin)
.\scripts\apply-cis-baseline.ps1

# 3. Aplicar solo hardening de PowerShell
.\scripts\powershell-hardening.ps1

# 4. Aplicar ASR Rules de Defender
.\scripts\defender-hardening.ps1

# 5. Verificar cumplimiento post-aplicación
.\scripts\check-compliance.ps1 -Report
```

> ⚠️ Probar siempre en entorno de lab antes de aplicar en producción. Ver docs/impacto-operativo.md

---

## 🔗 Referencias

- [CIS Benchmark Windows 10](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
- [MITRE ATT&CK Mitigations](https://attack.mitre.org/mitigations/)
- [ASR Rules Reference](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)

---

<div align="center">
<sub>Hardening documentado · Cada control incluye justificación técnica y verificación</sub>
</div>
