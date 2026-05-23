#!/bin/bash
# ssh-hardening.sh
# Hardening de SSH basado en CIS Benchmark y Mozilla SSH Guidelines
# Compatible: Ubuntu 20.04 / 22.04, Debian 11/12
# Autor: briamrlz82

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# Verificar root
[[ $EUID -ne 0 ]] && { echo -e "${RED}[ERROR]${NC} Ejecutar como root"; exit 1; }

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"

info "=== SSH Hardening ==="
info "Backup de configuración actual → $BACKUP"
cp "$SSHD_CONFIG" "$BACKUP"

# Función para setear o agregar directiva SSH
set_ssh_config() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?${key}" "$SSHD_CONFIG"; then
        sed -i "s|^#\?${key}.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# ── Protocolo y puerto ───────────────────────────────────────────
info "Configurando protocolo y puerto..."
set_ssh_config "Protocol" "2"
set_ssh_config "Port" "2222"
ok "Protocol 2, Puerto 2222"

# ── Autenticación ────────────────────────────────────────────────
info "Configurando autenticación..."
set_ssh_config "PermitRootLogin" "no"
set_ssh_config "PasswordAuthentication" "no"
set_ssh_config "PubkeyAuthentication" "yes"
set_ssh_config "AuthorizedKeysFile" ".ssh/authorized_keys"
set_ssh_config "PermitEmptyPasswords" "no"
set_ssh_config "ChallengeResponseAuthentication" "no"
set_ssh_config "UsePAM" "yes"
set_ssh_config "MaxAuthTries" "3"
set_ssh_config "MaxSessions" "3"
ok "Root login: NO | Password auth: NO | MaxAuthTries: 3"

# ── Timeout de sesión ────────────────────────────────────────────
info "Configurando timeouts..."
set_ssh_config "ClientAliveInterval" "300"
set_ssh_config "ClientAliveCountMax" "2"
set_ssh_config "LoginGraceTime" "30"
ok "Timeout: 300s × 2 = 10 minutos máximo de inactividad"

# ── Restricciones de acceso ──────────────────────────────────────
info "Configurando restricciones..."
set_ssh_config "AllowAgentForwarding" "no"
set_ssh_config "AllowTcpForwarding" "no"
set_ssh_config "X11Forwarding" "no"
set_ssh_config "PrintMotd" "no"
set_ssh_config "Banner" "/etc/issue.net"
ok "Forwarding: NO | X11: NO"

# ── Algoritmos criptográficos seguros (Mozilla Modern) ───────────
info "Configurando algoritmos criptográficos..."
set_ssh_config "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
set_ssh_config "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
set_ssh_config "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
set_ssh_config "HostKeyAlgorithms" "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256"
ok "Algoritmos modernos configurados (curve25519, chacha20, ed25519)"

# ── Banner de advertencia ────────────────────────────────────────
info "Configurando banner..."
cat > /etc/issue.net << 'BANNER'
*******************************************************************
*         ACCESO AUTORIZADO SOLAMENTE                            *
*  Este sistema es monitoreado. Toda actividad es registrada.    *
*  El acceso no autorizado está prohibido y será perseguido.     *
*******************************************************************
BANNER
ok "Banner configurado"

# ── Validar configuración y reiniciar ────────────────────────────
info "Validando configuración SSH..."
if sshd -t; then
    ok "Configuración válida"
    info "Reiniciando SSH..."
    systemctl restart sshd
    ok "SSH reiniciado"
else
    warn "ERROR en la configuración — restaurando backup"
    cp "$BACKUP" "$SSHD_CONFIG"
    systemctl restart sshd
    exit 1
fi

# ── Abrir nuevo puerto en UFW si está activo ─────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw allow 2222/tcp comment "SSH hardened"
    ufw delete allow 22/tcp 2>/dev/null || true
    ok "UFW actualizado: 2222/tcp abierto, 22/tcp cerrado"
fi

echo ""
info "=== RESUMEN ==="
ok "Puerto SSH          → 2222"
ok "Root login          → DESHABILITADO"
ok "Password auth       → DESHABILITADO"
ok "MaxAuthTries        → 3"
ok "Timeout sesión      → 10 minutos"
ok "Algoritmos          → Modernos (Ed25519, ChaCha20)"
echo ""
warn "IMPORTANTE: Asegurate de tener tu clave pública en ~/.ssh/authorized_keys"
warn "antes de cerrar esta sesión, o perderás el acceso SSH."
warn "Probar conexión: ssh -p 2222 usuario@servidor"
