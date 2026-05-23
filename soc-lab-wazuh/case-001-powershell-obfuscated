# 🔵 SOC Lab — Wazuh + Sysmon + Detection Engineering

> Laboratorio de detección activa con Wazuh SIEM, Sysmon y reglas personalizadas mapeadas a MITRE ATT&CK.

[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.x-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![Status](https://img.shields.io/badge/Status-Activo-00ff88?style=for-the-badge)](.)

---

## 🎯 Objetivo

Este laboratorio demuestra capacidad real de **Detection Engineering**: diseñar, implementar y documentar reglas de detección basadas en comportamiento adversario real, usando herramientas de nivel enterprise.

No es un tutorial. Es un laboratorio operativo con casos documentados como lo haría un analista SOC.

---

## 🏗️ Arquitectura del laboratorio

```
┌─────────────────────────────────────────────────────────┐
│                     RED DE LAB                          │
│                                                         │
│  ┌──────────────┐      ┌──────────────────────────┐    │
│  │  Windows 10  │      │     Wazuh Manager         │    │
│  │  + Sysmon    │─────▶│     + Elasticsearch       │    │
│  │  + Agent     │      │     + Kibana               │    │
│  └──────────────┘      └──────────────────────────┘    │
│                                                         │
│  ┌──────────────┐                                       │
│  │  Kali Linux  │  ← máquina atacante                  │
│  │  (atacante)  │                                       │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

| Componente | Versión | Rol |
|-----------|---------|-----|
| Wazuh Manager | 4.7.x | SIEM / correlación |
| Wazuh Agent | 4.7.x | Recolección en endpoint |
| Sysmon | 15.x | Telemetría avanzada de Windows |
| Elasticsearch | 8.x | Almacenamiento e indexación |
| Kibana | 8.x | Visualización y dashboards |
| Windows 10 | 22H2 | Endpoint víctima |
| Kali Linux | 2024.x | Plataforma de ataque |

---

## 📂 Estructura del repositorio

```
soc-lab-wazuh/
│
├── 📄 README.md                         ← Este archivo
├── 📂 docs/
│   ├── setup-wazuh.md                  ← Instalación y configuración
│   ├── setup-sysmon.md                 ← Configuración Sysmon
│   └── arquitectura.md                 ← Diagrama detallado del lab
│
├── 📂 sysmon/
│   └── sysmon-config.xml               ← Configuración Sysmon (basada en SwiftOnSecurity)
│
├── 📂 rules/
│   ├── wazuh/                          ← Reglas XML para Wazuh
│   │   ├── powershell_detection.xml
│   │   ├── lolbas_detection.xml
│   │   └── lateral_movement.xml
│   └── sigma/                          ← Reglas Sigma originales
│       ├── powershell_obfuscation.yml
│       ├── encoded_commands.yml
│       └── suspicious_processes.yml
│
├── 📂 cases/                           ← Casos documentados
│   └── case-001-powershell-obfuscated/
│       ├── README.md                   ← Análisis completo del caso
│       ├── alert-sample.json           ← Alerta real de Wazuh
│       └── screenshots/
│
├── 📂 dashboards/
│   └── kibana-soc-dashboard.ndjson     ← Dashboard importable
│
└── 📂 scripts/
    ├── test-detections.ps1             ← Simula ataques para probar reglas
    └── export-alerts.py               ← Exporta alertas desde Wazuh API
```

---

## 🔍 Casos de detección documentados

| # | Caso | Táctica MITRE | Técnica | Estado |
|---|------|--------------|---------|--------|
| 001 | [PowerShell obfuscado con EncodedCommand](./cases/case-001-powershell-obfuscated/) | Execution | T1059.001 | ✅ Documentado |
| 002 | LOLBAS — certutil descargando payload | Defense Evasion | T1218 | 🔄 En progreso |
| 003 | Mimikatz — volcado de credenciales | Credential Access | T1003.001 | 📋 Planificado |
| 004 | Lateral movement via PsExec | Lateral Movement | T1570 | 📋 Planificado |
| 005 | Persistence via scheduled task | Persistence | T1053.005 | 📋 Planificado |

---

## 🛠️ Setup rápido

### Requisitos
- 2 VMs mínimo (Windows 10 + Ubuntu para Wazuh)
- 8 GB RAM recomendado
- VirtualBox o VMware

### Instalación Wazuh
```bash
# En Ubuntu Server
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash wazuh-install.sh -a
```

Ver guía completa: [docs/setup-wazuh.md](./docs/setup-wazuh.md)

### Instalar Sysmon en Windows
```powershell
# Descargar Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip

# Instalar con config del repo
.\Sysmon64.exe -accepteula -i .\sysmon\sysmon-config.xml
```

### Cargar reglas personalizadas
```bash
# En Wazuh Manager
cp rules/wazuh/*.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

---

## 📊 Cobertura MITRE ATT&CK

```
TA0002 Execution          ████████░░  [T1059.001 PowerShell]
TA0005 Defense Evasion    ██████░░░░  [T1218 LOLBAS]
TA0006 Credential Access  ████░░░░░░  [T1003 OS Credential Dumping]
TA0008 Lateral Movement   ██░░░░░░░░  [T1570 Transfer Tool]
TA0003 Persistence        ██░░░░░░░░  [T1053 Scheduled Task]
```

---

## 📝 Metodología de cada caso

Cada caso documentado sigue este formato:

1. **Contexto** — Qué amenaza representa esta técnica
2. **Reproducción** — Cómo simular el ataque en el lab
3. **Logs generados** — Eventos de Windows/Sysmon relevantes
4. **Regla implementada** — Sigma + Wazuh con explicación
5. **Alerta real** — JSON de la alerta disparada
6. **Falsos positivos** — Qué puede generar ruido y cómo filtrarlo
7. **Mitigación** — Controles para reducir superficie de ataque

---

## 🔗 Referencias

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Sysmon Config — SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

<div align="center">
<sub>Laboratorio activo · Los casos se documentan con evidencia real del entorno</sub>
</div>
