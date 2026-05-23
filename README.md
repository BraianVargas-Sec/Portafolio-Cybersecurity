<div align="center">

```
╔══════════════════════════════════════════════════════╗
║          CYBERSECURITY PORTFOLIO                     ║
║          Brian · SOC · Detection · DevSecOps         ║
╚══════════════════════════════════════════════════════╝
```

[![SOC](https://img.shields.io/badge/Role-SOC%20Analyst-0d1117?style=for-the-badge&logo=shield&logoColor=00ff88)](.)
[![Detection](https://img.shields.io/badge/Focus-Detection%20Engineering-0d1117?style=for-the-badge&logo=searchengineland&logoColor=00ff88)](.)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Pipeline%20Security-0d1117?style=for-the-badge&logo=github-actions&logoColor=00ff88)](.)
[![AI](https://img.shields.io/badge/AI-Applied%20to%20Security-0d1117?style=for-the-badge&logo=openai&logoColor=00ff88)](.)

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
| 🔴 Pentesting | Active Directory · Kerberoasting · PTH | ███████░░░ Medio |
| 🟡 DevSecOps | Docker · CI/CD · Trivy · Gitleaks | ████████░░ Creciendo |
| 🟣 IA aplicada | Python · LLMs · Automatización SOC | ████████░░ Creciendo |

---

## 🏗️ Estructura del portafolio

```
Portafolio-Ciberseguridad/
│
├── 📂 wazuh/                    # SIEM Lab - reglas, alertas, integraciones
├── 📂 windows-hardening/        # CIS Benchmark, GPOs, Defender, ASR Rules
├── 📂 linux-hardening/          # SSH, Fail2ban, Auditd, UFW
├── 📂 ad-pentest-lab/           # Active Directory attacks & detection
├── 📂 detection-rules/          # Sigma rules → Wazuh, MITRE mapping
├── 📂 devsecops-pipeline/       # CI/CD con SAST, Trivy, Gitleaks
├── 📂 incident-response/        # Playbooks y casos reales documentados
├── 📂 ai-soc-assistant/         # IA aplicada al análisis de alertas
├── 📂 writeups/                 # CTFs y laboratorios documentados
└── 📂 PowerShell/               # Scripts de detección y automatización
```

---

## 🚀 Proyectos destacados

### 🔵 [soc-lab-wazuh](./wazuh)
> Laboratorio completo de detección con Wazuh + Sysmon + reglas personalizadas

- Detección de PowerShell malicioso (obfuscation, encoded commands, AMSI bypass)
- Reglas Sigma convertidas a formato Wazuh
- Mapeo a MITRE ATT&CK por táctica y técnica
- Integración con Active Directory para correlación de eventos
- Dashboards de Kibana para visualización de amenazas

**Stack:** `Wazuh` `Sysmon` `Windows Event Logs` `Python` `Sigma`

---

### 🟢 [windows-hardening](./windows-hardening)
> Hardening de sistemas Windows basado en CIS Benchmark v2.0

- Scripts PowerShell para aplicar controles CIS automáticamente
- Políticas de grupo (GPO) exportadas y documentadas
- Configuración de Defender Hardening + ASR Rules
- PowerShell Logging (ScriptBlock, Module, Transcription)
- Implementación de LAPS para gestión de contraseñas locales

**Stack:** `PowerShell` `Group Policy` `Windows Server` `CIS Controls`

---

### 🔴 [ad-pentest-lab](./ad-pentest-lab)
> Laboratorio de Active Directory: ataques, detección y mitigación

- Entorno AD vulnerable en VMs locales
- Técnicas: Kerberoasting, Pass-the-Hash, AS-REP Roasting, BloodHound
- Por cada ataque: regla de detección en Wazuh + mitigación documentada
- Reportes técnicos en formato profesional

**Stack:** `Active Directory` `Impacket` `BloodHound` `Wazuh` `PowerShell`

---

### 🟡 [devsecops-pipeline](./devsecops-pipeline)
> Pipeline CI/CD con seguridad integrada desde el código hasta el contenedor

- SAST con Semgrep integrado en GitHub Actions
- Escaneo de contenedores con Trivy
- Detección de secrets con Gitleaks
- Docker hardening (non-root, read-only FS, capabilities drop)
- Políticas de seguridad como código

**Stack:** `GitHub Actions` `Docker` `Trivy` `Gitleaks` `Semgrep`

---

### 🟣 [ai-soc-assistant](./ai-soc-assistant)
> Asistente de IA para análisis y triaje de alertas de seguridad

- Integración con API de Wazuh para ingesta de alertas
- Clasificación automática de eventos por severidad y táctica MITRE
- Generación de resúmenes ejecutivos para el equipo SOC
- Respuesta automatizada a incidentes de baja complejidad

**Stack:** `Python` `Wazuh API` `LLMs` `Docker`

---

## 🛡️ Stack técnico

```
DEFENSA                          OFENSIVA
──────────────────────────────   ──────────────────────────────
Wazuh          ████████████     Metasploit     ████░░░░░░░░
Sysmon         ████████████     Impacket       ████████░░░░
Elastic Stack  ████████░░░░     BloodHound     ██████░░░░░░
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

Cada proyecto de este portafolio incluye:

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
[![Email](https://img.shields.io/badge/Email-Contacto-D14836?style=for-the-badge&logo=gmail)](mailto:braii3015@gmail.com)

*Abierto a oportunidades en SOC, Detection Engineering y DevSecOps*

</div>

---

<div align="center">
<sub>Este portafolio documenta trabajo práctico real. Cada proyecto incluye evidencias, metodología y código funcional.</sub>
</div>
