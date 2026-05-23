# 🟣 AI SOC Assistant — Análisis de alertas Wazuh con IA

> Asistente de IA que analiza alertas de Wazuh en tiempo real, clasifica eventos por severidad y táctica MITRE ATT&CK, y genera resúmenes ejecutivos para el equipo SOC.

[![Python](https://img.shields.io/badge/Python-3.10+-0d1117?style=for-the-badge&logo=python&logoColor=00ff88)](.)
[![Wazuh](https://img.shields.io/badge/Integración-Wazuh%20API-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![Status](https://img.shields.io/badge/Status-Activo-00ff88?style=for-the-badge)](.)

---

## 🎯 Objetivo

Aplicar IA al análisis de alertas de seguridad para:

- **Reducir el tiempo de triaje** — clasificar alertas automáticamente por prioridad
- **Enriquecer contexto** — mapear cada alerta a MITRE ATT&CK con explicación
- **Detectar patrones** — identificar cadenas de ataque entre múltiples alertas
- **Generar reportes** — resúmenes ejecutivos listos para el equipo SOC

> Este proyecto demuestra cómo la IA puede asistir al analista SOC sin reemplazarlo — aumentando su capacidad de respuesta.

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    AI SOC Assistant                         │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Wazuh API  │───▶│   Analyzer   │───▶│  LLM Engine   │  │
│  │  (alertas)  │    │  (Python)    │    │  (Claude API) │  │
│  └─────────────┘    └──────────────┘    └───────────────┘  │
│                            │                                │
│                     ┌──────▼──────┐                        │
│                     │   Output    │                        │
│                     │  - Triaje   │                        │
│                     │  - MITRE    │                        │
│                     │  - Reporte  │                        │
│                     └─────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 📂 Estructura

```
ai-soc-assistant/
│
├── 📄 README.md
├── 📄 requirements.txt
├── 📄 .env.example                 ← Variables de entorno (sin credenciales reales)
│
├── 📂 src/
│   ├── main.py                    ← Entry point
│   ├── wazuh_client.py            ← Cliente de la API de Wazuh
│   ├── alert_analyzer.py          ← Análisis y clasificación de alertas
│   ├── llm_engine.py              ← Integración con LLM (Claude/OpenAI)
│   └── report_generator.py        ← Generación de reportes
│
├── 📂 prompts/
│   ├── triage_prompt.txt          ← Prompt para triaje de alertas
│   └── report_prompt.txt          ← Prompt para generación de reportes
│
└── 📂 examples/
    ├── sample_alerts.json         ← Alertas de ejemplo para testing
    └── sample_report.md           ← Ejemplo de reporte generado
```

---

## 🚀 Instalación y uso

```bash
# Clonar el repo
git clone https://github.com/briamrlz82/Portafolio-Cybersecurity
cd ai-soc-assistant

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales

# Ejecutar análisis
python src/main.py --mode triage          # Triaje de últimas alertas
python src/main.py --mode report          # Generar reporte ejecutivo
python src/main.py --mode watch           # Monitoreo continuo
```

---

## 📊 Ejemplo de output

```
═══════════════════════════════════════════════════
  AI SOC ASSISTANT — Análisis de Alertas
  2024-02-10 03:44:18 UTC
═══════════════════════════════════════════════════

ALERTAS ANALIZADAS: 47
CRÍTICAS:  3  ████ 
ALTAS:     8  ████████
MEDIAS:   21  █████████████████████
BAJAS:    15  ███████████████

─── INCIDENTE DETECTADO ───────────────────────────
🔴 CRÍTICO — Posible cadena de ataque en DESKTOP-01

Secuencia detectada:
  14:22 → PowerShell EncodedCommand    [T1059.001]
  14:23 → LSASS Memory Access          [T1003.001]  
  14:31 → PsExec hacia DESKTOP-02      [T1570]

Análisis: Patrón consistente con post-explotación.
El atacante ejecutó PowerShell ofuscado, volcó
credenciales de LSASS y usó PsExec para moverse
lateralmente. Alta confianza: ransomware en progreso.

Acción recomendada: CONTENER DESKTOP-01 y DESKTOP-02
inmediatamente. Aislar de la red. Iniciar IR.
═══════════════════════════════════════════════════
```

---

## 🔧 Configuración

```env
# .env.example
WAZUH_HOST=https://wazuh-manager:55000
WAZUH_USER=wazuh-user
WAZUH_PASSWORD=your-password
ANTHROPIC_API_KEY=your-api-key
ALERT_LIMIT=100
TRIAGE_INTERVAL=300
```

---

## 🔗 Referencias

- [Wazuh API Documentation](https://documentation.wazuh.com/current/user-manual/api/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Anthropic Claude API](https://docs.anthropic.com/)

---

<div align="center">
<sub>IA aplicada a ciberseguridad · Triaje automatizado · Detección de cadenas de ataque</sub>
</div>
