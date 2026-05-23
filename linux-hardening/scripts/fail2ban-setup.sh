#!/bin/bash
# fail2ban-setup.sh
# Instalación y configuración de Fail2ban para protección contra fuerza bruta
# Compatible: Ubuntu 20.04 / 22.04, Debian 11/12
# Autor: briamrlz82

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo "[ERROR] Ejecutar como root"; exit 1; }

info "=== Fail2ban Setup ==="

# ── Instalación ──────────────────────────────────────────────────
info "Instalando Fail2ban..."
apt-get update -qq
apt-get install -y fail2ban
ok "Fail2ban instalado"

# ── Configuración principal ──────────────────────────────────────
info "Configurando jail.local..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Tiempo de ban en segundos (3600 = 1 hora)
bantime  = 3600

# Ventana de tiempo para contar intentos (600 = 10 minutos)
findtime = 600

# Número de intentos antes del ban
maxretry = 3

# Backend de logs
backend = systemd

# Ignorar IPs locales
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

# Acción de ban: bloquear con iptables y notificar
banaction = iptables-multiport
banaction_allports = iptables-allports

# ── SSH ──────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600

# SSH agresivo: ban más largo para atacantes reincidentes
[sshd-aggressive]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = 86400
bantime  = 86400

# ── Nginx (si aplica) ────────────────────────────────────────────
[nginx-http-auth]
enabled  = false
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled  = false
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10

# ── Postfix (si aplica) ──────────────────────────────────────────
[postfix]
enabled  = false
port     = smtp,465,submission
logpath  = /var/log/mail.log
maxretry = 3
EOF

ok "jail.local configurado"

# ── Habilitar e iniciar ──────────────────────────────────────────
info "Habilitando Fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban
ok "Fail2ban activo y habilitado en el arranque"

# ── Verificación ─────────────────────────────────────────────────
echo ""
info "=== VERIFICACIÓN ==="
fail2ban-client status
echo ""
ok "Estado del jail SSH:"
fail2ban-client status sshd || warn "El jail sshd aún no tiene actividad"

echo ""
info "Comandos útiles:"
echo "  fail2ban-client status sshd          # Estado del jail SSH"
echo "  fail2ban-client set sshd unbanip IP  # Desbanear una IP"
echo "  fail2ban-client banned               # Ver todas las IPs baneadas"
echo "  tail -f /var/log/fail2ban.log        # Ver logs en tiempo real"
