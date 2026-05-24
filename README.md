<div align="center">

```
╔══════════════════════════════════════════════════════╗
║          CYBERSECURITY PORTFOLIO                     ║
║          Brian · SOC · Red Team · DevSecOps          ║
╚══════════════════════════════════════════════════════╝
```

![SOC](https://img.shields.io/badge/Role-SOC%20Analyst-0d1117?style=for-the-badge&logo=shield&logoColor=00ff88)
![Detection](https://img.shields.io/badge/Focus-Detection%20Engineering-0d1117?style=for-the-badge&logoColor=00ff88)
![RedTeam](https://img.shields.io/badge/Red%20Team-AD%20%2F%20Evasion-0d1117?style=for-the-badge&logoColor=ff4444)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Pipeline%20Security-0d1117?style=for-the-badge&logo=github-actions&logoColor=00ff88)
![AI](https://img.shields.io/badge/AI-Applied%20to%20Security-0d1117?style=for-the-badge&logo=openai&logoColor=00ff88)

</div>

---

## 👤 Sobre mí

Analista de ciberseguridad con foco en **detección, respuesta y defensa activa**. Trabajo en IT y estudio la Licenciatura en Ciberseguridad. Mi diferencial: combino operación real con automatización, scripting y aplicación de IA en entornos de seguridad.

> *"No basta con detectar. Hay que entender, documentar y mejorar el sistema."*

---

## 🧠 Áreas de especialización

| Área | Tecnologías | Nivel |
|------|------------|-------|
| 🔵 SOC & Detection Engineering | Wazuh · Sysmon · Sigma · MITRE ATT&CK | ██████████ Activo |
| 🟢 Hardening | CIS Benchmark · GPO · Auditd · Fail2ban | █████████░ Alto |
| 🔴 Red Team / Pentesting | Active Directory · Evasion · C2 | ███████░░░ Medio-Alto |
| 🟡 DevSecOps | Docker · CI/CD · Trivy · Gitleaks | ████████░░ Creciendo |
| 🟣 IA aplicada | Python · LLMs · Automatización SOC | ████████░░ Creciendo |

---

## 🏗️ Estructura del portafolio

```
Portafolio-Ciberseguridad/
│
├── 📂 soc-lab-wazuh/           # SIEM Lab — detección + MITRE ATT&CK
├── 📂 windows-hardening/       # CIS Benchmark + scripts PowerShell
├── 📂 linux-hardening/         # SSH + Fail2ban + Auditd + UFW
├── 📂 ad-pentest-lab/          # Active Directory attacks & detection
├── 📂 evasion-techniques/      # Bypass AV/EDR + AMSI
├── 📂 devsecops-pipeline/      # CI/CD con SAST + Trivy + Gitleaks
└── 📂 ai-soc-assistant/        # IA aplicada al análisis de alertas
```

---

## 🚀 Proyectos

### 🔵 [soc-lab-wazuh](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/soc-lab-wazuh)
> Laboratorio completo de detección con Wazuh + Sysmon + reglas mapeadas a MITRE ATT&CK

| Case | Técnica | MITRE | 
|------|---------|-------|
| 001 | PowerShell EncodedCommand | T1059.001 |
| 002 | LOLBAS — certutil | T1218 |
| 003 | Mimikatz / LSASS dump | T1003.001 |
| 004 | Lateral Movement PsExec | T1570 |

**Stack:** `Wazuh` `Sysmon` `Sigma` `Windows Event Logs` `Python`

---

### 🟢 [windows-hardening](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/windows-hardening)
> Hardening de sistemas Windows basado en CIS Benchmark v2.0

- Scripts PowerShell para aplicar controles CIS automáticamente
- 10 ASR Rules configuradas con modo Block/Audit
- PowerShell Logging (ScriptBlock, Module, Transcription)
- Credential Guard, PPL para LSASS, WDigest deshabilitado

**Stack:** `PowerShell` `CIS Benchmark` `Windows Defender` `GPO`

---

### 🐧 [linux-hardening](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/linux-hardening)
> Hardening de sistemas Linux (Ubuntu/Debian) con scripts automatizados

- SSH hardening con algoritmos modernos (Ed25519, ChaCha20)
- Fail2ban con jails SSH agresivo (ban 24h)
- Auditd con reglas para /etc/passwd, sudo, execve, módulos kernel
- UFW con política default deny + rate limiting

**Stack:** `Bash` `SSH` `Fail2ban` `Auditd` `UFW` `CIS Benchmark`

---

### 🔴 [ad-pentest-lab](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/ad-pentest-lab)
> Laboratorio de Active Directory: ataques, detección y mitigación

- Kerberoasting con Impacket + detección por encryption type 0x17
- Pass-the-Hash con CrackMapExec + LAPS como mitigación
- Por cada ataque: regla de detección en Wazuh + mitigación documentada

**Stack:** `Active Directory` `Impacket` `BloodHound` `CrackMapExec` `Wazuh`

---

### 🔴 [evasion-techniques](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/evasion-techniques)
> Bypass de AV/EDR y AMSI — técnicas ofensivas con contrapartida defensiva

- AMSI bypass via memory patching y .NET Reflection
- Defender evasion: obfuscación, exclusiones, payloads fileless
- Para cada técnica: cómo detectarla desde el SOC con Wazuh

**Stack:** `PowerShell` `Windows Internals` `AMSI` `Windows Defender`

---

### 🟡 [devsecops-pipeline](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/devsecops-pipeline)
> Pipeline CI/CD con seguridad integrada en cada etapa

- Gitleaks para detección de secrets en código
- Trivy para escaneo de CVEs en imágenes Docker y dependencias
- Semgrep para análisis estático (SAST)
- Dockerfile hardened: non-root, multi-stage, sin herramientas innecesarias

**Stack:** `GitHub Actions` `Docker` `Trivy` `Gitleaks` `Semgrep` `Hadolint`

---

### 🟣 [ai-soc-assistant](https://github.com/briamrlz82/Portafolio-Cybersecurity/tree/main/ai-soc-assistant)
> Asistente de IA para análisis y triaje de alertas de seguridad

- Integración con API de Wazuh para ingesta de alertas en tiempo real
- Clasificación automática por severidad y táctica MITRE ATT&CK
- Generación de resúmenes ejecutivos para el equipo SOC
- Stack Python con arquitectura modular

**Stack:** `Python` `Wazuh API` `LLMs` `MITRE ATT&CK`

---

## 🛡️ Stack técnico

```
DEFENSA                          OFENSIVA
──────────────────────────────   ──────────────────────────────
Wazuh          ████████████     Impacket       ████████░░░░
Sysmon         ████████████     BloodHound     ██████░░░░░░
Elastic Stack  ████████░░░░     CrackMapExec   ██████░░░░░░
Suricata       ██████░░░░░░     Burp Suite     ██████░░░░░░
Zeek           ████░░░░░░░░     Nmap/Nessus    ████████░░░░

SCRIPTING & AUTOMATION           INFRAESTRUCTURA
──────────────────────────────   ──────────────────────────────
PowerShell     ████████████     Docker         ████████░░░░
Python         ████████░░░░     GitHub Actions ████████░░░░
Bash           ████████░░░░     Linux Server   ████████████
Sigma          ██████░░░░░░     Windows Server ████████████
```

---

## 📚 Formación y certificaciones

- 🎓 Licenciatura en Ciberseguridad *(en curso)*
- 🏢 Trabajo activo en IT con foco en seguridad
- 📖 Estudiando: **CompTIA Security+** · **Wazuh Certification**
- 🧪 Laboratorio propio con infraestructura real

---

## 📊 Metodología de trabajo

Cada proyecto incluye:

```
1. CONTEXTO     → Qué problema resuelve / qué amenaza detecta
2. LABORATORIO  → Cómo reproducir el entorno
3. EVIDENCIA    → Logs, screenshots, alertas reales
4. REGLA        → Detección implementada (Sigma/Wazuh)
5. MITIGACIÓN   → Controles aplicados y resultado
6. REFERENCIAS  → MITRE ATT&CK, CVEs, documentación
```

---

## 📫 Contacto

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-briamrlz82-0077B5?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/briamrlz82)
[![GitHub](https://img.shields.io/badge/GitHub-briamrlz82-181717?style=for-the-badge&logo=github)](https://github.com/briamrlz82)

*Abierto a oportunidades en SOC, Detection Engineering, Red Team y DevSecOps*

</div>

---

<div align="center">
<sub>Este portafolio documenta trabajo práctico real. Cada proyecto incluye evidencias, metodología y código funcional.</sub>
</div>
