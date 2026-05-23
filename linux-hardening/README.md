# 🐧 Linux Hardening — CIS Benchmark + Scripts Bash

> Hardening de sistemas Linux (Ubuntu/Debian) basado en CIS Benchmark, con scripts automatizados, configuraciones documentadas y verificación de cumplimiento.

[![CIS](https://img.shields.io/badge/Basado%20en-CIS%20Benchmark%20Linux-0d1117?style=for-the-badge&logoColor=00ff88)](.)
[![Bash](https://img.shields.io/badge/Bash-Automatizado-0d1117?style=for-the-badge&logo=gnubash&logoColor=00ff88)](.)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%20%2F%2022.04-0d1117?style=for-the-badge&logo=ubuntu&logoColor=00ff88)](.)
[![Status](https://img.shields.io/badge/Status-Activo-00ff88?style=for-the-badge)](.)

---

## 🎯 Objetivo

Implementar controles de seguridad en sistemas Linux siguiendo el estándar **CIS Benchmark**, cubriendo:

- Hardening de SSH para acceso remoto seguro
- Protección contra fuerza bruta con Fail2ban
- Auditoría de eventos del sistema con Auditd
- Control de tráfico de red con UFW
- Configuraciones de kernel y sistema

---

## 📂 Estructura

```
linux-hardening/
│
├── 📄 README.md
├── 📂 scripts/
│   ├── apply-hardening.sh          ← Script principal
│   ├── ssh-hardening.sh            ← Hardening de SSH
│   ├── fail2ban-setup.sh           ← Instalación y config de Fail2ban
│   ├── auditd-setup.sh             ← Configuración de Auditd
│   ├── ufw-setup.sh                ← Reglas de firewall UFW
│   └── check-compliance.sh         ← Verificación de controles
│
└── 📂 configs/
    ├── sshd_config                 ← Configuración SSH hardened
    ├── jail.local                  ← Configuración Fail2ban
    ├── audit.rules                 ← Reglas de Auditd
    └── ufw-rules.sh                ← Reglas UFW documentadas
```

---

## 🛡️ Controles implementados

### 🔐 SSH Hardening

| Control | Configuración | Valor |
|---------|--------------|-------|
| Puerto SSH | Cambiar del 22 | 2222 (recomendado) |
| Root login | Deshabilitar | `PermitRootLogin no` |
| Autenticación por contraseña | Deshabilitar | `PasswordAuthentication no` |
| Autenticación por clave | Habilitar | `PubkeyAuthentication yes` |
| Máx intentos de auth | Limitar | `MaxAuthTries 3` |
| Timeout de sesión | Configurar | `ClientAliveInterval 300` |
| Protocolo SSH | Solo v2 | `Protocol 2` |
| Algoritmos débiles | Deshabilitar | MACs y Ciphers seguros |

### 🚫 Fail2ban

| Jail | Servicio | Intentos | Ban |
|------|---------|----------|-----|
| sshd | SSH | 3 intentos | 1 hora |
| sshd-aggressive | SSH agresivo | 3 intentos | 24 horas |
| nginx-http-auth | Nginx | 5 intentos | 1 hora |
| postfix | Mail | 3 intentos | 1 hora |

### 📋 Auditd — Reglas de auditoría

| Categoría | Eventos monitoreados |
|-----------|---------------------|
| Autenticación | Login, sudo, su, cambios de contraseña |
| Archivos críticos | /etc/passwd, /etc/shadow, /etc/sudoers |
| Comandos privilegiados | Todos los binarios SUID/SGID |
| Acceso a red | Cambios de configuración de red |
| Módulos del kernel | Carga/descarga de módulos |
| Llamadas al sistema | execve, open, unlink en rutas críticas |

### 🔥 UFW — Firewall

| Regla | Dirección | Puerto | Acción |
|-------|-----------|--------|--------|
| Default | Entrante | Todos | DENY |
| Default | Saliente | Todos | ALLOW |
| SSH | Entrante | 2222/tcp | ALLOW |
| HTTP | Entrante | 80/tcp | ALLOW (si aplica) |
| HTTPS | Entrante | 443/tcp | ALLOW (si aplica) |
| Wazuh Agent | Saliente | 1514/tcp | ALLOW |

### ⚙️ Kernel y sistema

| Control | Configuración | Valor |
|---------|--------------|-------|
| IP forwarding | Deshabilitar | `net.ipv4.ip_forward = 0` |
| ICMP redirects | Deshabilitar | `net.ipv4.conf.all.accept_redirects = 0` |
| SYN cookies | Habilitar | `net.ipv4.tcp_syncookies = 1` |
| Core dumps | Deshabilitar | `fs.suid_dumpable = 0` |
| ASLR | Habilitar máximo | `kernel.randomize_va_space = 2` |

---

## 🚀 Uso rápido

```bash
# Clonar el repo
git clone https://github.com/briamrlz82/Portafolio-Cybersecurity
cd linux-hardening

# Dar permisos de ejecución
chmod +x scripts/*.sh

# Verificar estado actual
sudo ./scripts/check-compliance.sh

# Aplicar hardening completo
sudo ./scripts/apply-hardening.sh

# O aplicar por módulo
sudo ./scripts/ssh-hardening.sh
sudo ./scripts/fail2ban-setup.sh
sudo ./scripts/auditd-setup.sh
sudo ./scripts/ufw-setup.sh
```

> ⚠️ Probar siempre en VM antes de aplicar en producción. El hardening de SSH puede bloquear el acceso remoto si no se configura correctamente la clave primero.

---

## 🔗 Referencias

- [CIS Benchmark Ubuntu Linux](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [SSH Hardening Guide — Mozilla](https://infosec.mozilla.org/guidelines/openssh)
- [Fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/MANUAL_0_8)
- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)

---

<div align="center">
<sub>Hardening documentado · Cada control incluye justificación técnica y verificación</sub>
</div>
