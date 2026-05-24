# 🔴 Evasion Techniques — Bypass AV/EDR + AMSI

> Documentación técnica de técnicas de evasión de soluciones de seguridad: AMSI bypass, Defender evasion y conceptos de EDR evasion. Cada técnica incluye cómo funciona el mecanismo de defensa, cómo se bypasea y cómo detectarlo desde el lado defensivo.

[![RedTeam](https://img.shields.io/badge/Rol-Red%20Team-0d1117?style=for-the-badge&logoColor=ff4444)](.)
[![MITRE](https://img.shields.io/badge/MITRE-T1562%20Defense%20Evasion-0d1117?style=for-the-badge&logoColor=ff4444)](.)
[![Status](https://img.shields.io/badge/Status-Activo-ff4444?style=for-the-badge)](.)

---

## 🎯 Objetivo

Entender a fondo los mecanismos de defensa para poder:
1. **Bypassearlos** durante operaciones red team autorizadas
2. **Detectarlos** desde el lado del SOC/Blue Team
3. **Mejorar las defensas** basándose en lo que funciona y lo que no

> El mejor defensivo es quien entiende cómo piensa el atacante.

---

## ⚠️ Disclaimer

> Estas técnicas son para uso exclusivo en entornos autorizados y controlados. El objetivo es educativo: entender cómo funcionan los ataques para mejorar la detección y defensa. Usar estas técnicas sin autorización es ilegal.

---

## 📂 Estructura

```
evasion-techniques/
│
├── 📄 README.md
├── 📂 amsi/
│   └── 01-amsi-bypass.md             ← Memory patching + Reflection + detección
│
└── 📂 defender/
    └── 01-defender-evasion.md        ← Obfuscation + Exclusions + Fileless
```

---

## 🛡️ Técnicas documentadas

| # | Técnica | MITRE | Mecanismo bypasseado | Estado |
|---|---------|-------|---------------------|--------|
| 01 | AMSI Memory Patching | T1562.001 | AMSI | ✅ |
| 02 | AMSI via Reflection | T1562.001 | AMSI | ✅ |
| 03 | Defender String Obfuscation | T1027 | Signature detection | ✅ |
| 04 | Defender Exclusion Abuse | T1562.001 | Windows Defender | ✅ |
| 05 | Fileless Payload | T1059.001 | Disk-based scanning | ✅ |

---

## 🔄 Conexión con soc-lab-wazuh

Cada técnica de evasión tiene su contrapartida detectada en el soc-lab:

| Evasión (este repo) | Detección (soc-lab-wazuh) |
|--------------------|---------------------|
| AMSI bypass | Case 001 — Script Block Log (Event 4104) |
| Defender exclusion | Regla Wazuh 100080 |
| Fileless payload | Case 001 + Case 002 |
| String obfuscation | Case 001 — EncodedCommand |

---

## 🔗 Referencias

- [MITRE T1562 — Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [AMSI Documentation — Microsoft](https://docs.microsoft.com/en-us/windows/win32/amsi/)
- [ired.team — Defense Evasion](https://www.ired.team/offensive-security/defense-evasion)
- [rastamouse — AMSI research](https://rastamouse.me/memory-patching-amsi-bypass/)
