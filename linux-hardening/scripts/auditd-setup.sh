#!/bin/bash
# auditd-setup.sh
# Configuración de Auditd para auditoría de eventos del sistema
# Compatible: Ubuntu 20.04 / 22.04, Debian 11/12
# Autor: briamrlz82

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo "[ERROR] Ejecutar como root"; exit 1; }

info "=== Auditd Setup ==="

# ── Instalación ──────────────────────────────────────────────────
apt-get install -y auditd audispd-plugins
ok "Auditd instalado"

# ── Reglas de auditoría ──────────────────────────────────────────
info "Configurando reglas de auditoría..."
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
## Reglas de auditoría - Hardening baseline
## Autor: briamrlz82

# Limpiar reglas existentes
-D

# Buffer y configuración
-b 8192
--backlog_wait_time 60000

# ── Archivos críticos del sistema ────────────────────────────────
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
-w /etc/hosts -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# ── Autenticación y privilegios ──────────────────────────────────
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/lastlog -p rwa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc

# ── Módulos del kernel ───────────────────────────────────────────
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules

# ── Llamadas al sistema sospechosas ─────────────────────────────
# Creación de procesos
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# Cambios de identidad
-a always,exit -F arch=b64 -S setuid,setgid,seteuid,setegid -k identity_change
-a always,exit -F arch=b32 -S setuid,setgid,seteuid,setegid -k identity_change

# Acceso a red
-a always,exit -F arch=b64 -S socket,connect,accept,bind -k network_access

# ── Binarios SUID/SGID ───────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k elevated_privs

# ── Inmutabilidad (evitar modificación de reglas) ────────────────
-e 2
EOF

ok "Reglas de auditoría configuradas"

# ── Aplicar y habilitar ──────────────────────────────────────────
augenrules --load
systemctl enable auditd
systemctl restart auditd
ok "Auditd activo"

echo ""
info "Comandos útiles:"
echo "  auditctl -l                          # Ver reglas activas"
echo "  ausearch -k identity                 # Buscar eventos de identidad"
echo "  ausearch -k priv_esc                 # Buscar escaladas de privilegio"
echo "  aureport --auth                      # Reporte de autenticación"
echo "  aureport --failed                    # Eventos fallidos"
