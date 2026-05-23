# 🟡 DevSecOps Pipeline — Seguridad integrada en CI/CD

> Pipeline CI/CD con seguridad integrada en cada etapa: análisis estático de código (SAST), escaneo de dependencias, detección de secrets, hardening de contenedores y políticas de seguridad como código.

[![GitHub Actions](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-0d1117?style=for-the-badge&logo=github-actions&logoColor=00ff88)](.)
[![Docker](https://img.shields.io/badge/Containers-Docker%20Hardened-0d1117?style=for-the-badge&logo=docker&logoColor=00ff88)](.)
[![Trivy](https://img.shields.io/badge/Scanner-Trivy-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![Status](https://img.shields.io/badge/Status-Activo-00ff88?style=for-the-badge)](.)

---

## 🎯 Objetivo

Demostrar cómo integrar seguridad en el pipeline de desarrollo sin frenar la velocidad del equipo. El concepto "shift left": detectar vulnerabilidades lo antes posible, cuando son más baratas de corregir.

---

## 🏗️ Pipeline completo

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVSECOPS PIPELINE                           │
│                                                                 │
│  CODE          BUILD         TEST          DEPLOY               │
│  ────          ─────         ────          ──────               │
│  Gitleaks      Trivy         SAST          Docker               │
│  (secrets)     (CVEs)        Semgrep       hardened             │
│                              (code)                             │
│                                                                 │
│  ❌ Falla si   ❌ Falla si   ❌ Falla si   ✅ Solo si todo      │
│  hay secrets   hay CVEs      hay vulns     pasó anterior        │
│  en el código  críticos      críticas                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📂 Estructura

```
devsecops-pipeline/
│
├── 📄 README.md
├── 📂 .github/
│   └── workflows/
│       ├── security-pipeline.yml    ← Pipeline principal completo
│       └── secret-scan.yml          ← Escaneo de secrets en PRs
│
├── 📂 docker/
│   ├── Dockerfile.hardened          ← Dockerfile con mejores prácticas
│   └── docker-compose.yml           ← Compose con configuración segura
│
├── 📂 scripts/
│   ├── trivy-scan.sh                ← Escaneo local con Trivy
│   ├── gitleaks-scan.sh             ← Detección de secrets local
│   └── semgrep-scan.sh              ← SAST con Semgrep
│
└── 📂 docs/
    └── security-gates.md            ← Documentación de gates de seguridad
```

---

## 🔒 Herramientas integradas

| Herramienta | Etapa | Qué detecta | Falla el build |
|-------------|-------|-------------|----------------|
| **Gitleaks** | Pre-commit / PR | API keys, passwords, tokens en código | Sí |
| **Trivy** | Build | CVEs en imagen Docker y dependencias | Si severidad CRITICAL |
| **Semgrep** | Test | Vulnerabilidades en código (SAST) | Si severidad ERROR |
| **Hadolint** | Build | Malas prácticas en Dockerfile | Si nivel WARNING+ |

---

## 🚀 Uso local

```bash
# Escanear secrets en el repo
./scripts/gitleaks-scan.sh

# Escanear imagen Docker por CVEs
./scripts/trivy-scan.sh mi-imagen:latest

# Análisis estático del código
./scripts/semgrep-scan.sh ./src

# Build de imagen hardened
docker build -f docker/Dockerfile.hardened -t app:secure .
```

---

## 📊 Ejemplo de output — Trivy

```
mi-app:latest (ubuntu 22.04)
════════════════════════════════════════

Total: 3 (CRITICAL: 1, HIGH: 2)

┌──────────────┬───────────────┬──────────┬────────────────────┐
│   Library    │ Vulnerability │ Severity │      Title         │
├──────────────┼───────────────┼──────────┼────────────────────┤
│ openssl      │ CVE-2023-xxxx │ CRITICAL │ Buffer overflow    │
│ libssl       │ CVE-2023-yyyy │ HIGH     │ Memory leak        │
│ curl         │ CVE-2023-zzzz │ HIGH     │ Path traversal     │
└──────────────┴───────────────┴──────────┴────────────────────┘

❌ BUILD FALLIDO — CVEs críticos encontrados
   Actualizar dependencias antes de continuar
```

---

## 🔗 Referencias

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Semgrep](https://semgrep.dev/)
- [Hadolint](https://github.com/hadolint/hadolint)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)

---

<div align="center">
<sub>Seguridad integrada en CI/CD · Shift left · Fail fast</sub>
</div>
