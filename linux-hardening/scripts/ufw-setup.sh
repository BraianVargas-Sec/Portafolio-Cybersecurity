#!/bin/bash
# ufw-setup.sh
# Configuración de UFW (Uncomplicated Firewall) con política restrictiva
# Compatible: Ubuntu 20.04 / 22.04, Debian 11/12
# Autor: briamrlz82

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo "[ERROR] Ejecutar como root"; exit 1; }

# Variables — ajustar según entorno
SSH_PORT="${SSH_PORT:-2222}"
WAZUH_MANAGER="${WAZUH_MANAGER:-}"   # IP del Wazuh Manager (opcional)

info "=== UFW Firewall Setup ==="

# ── Instalación ──────────────────────────────────────────────────
apt-get install -y ufw
ok "UFW instalado"

# ── Política default ─────────────────────────────────────────────
info "Aplicando política default restrictiva..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
ok "Default: DENY incoming, ALLOW outgoing"

# ── Reglas de entrada ────────────────────────────────────────────
info "Configurando reglas de entrada..."
ufw allow "$SSH_PORT"/tcp comment "SSH hardened"
ok "SSH permitido en puerto $SSH_PORT"

# Descomentar según necesidades del servidor:
# ufw allow 80/tcp comment "HTTP"
# ufw allow 443/tcp comment "HTTPS"
# ufw allow 8080/tcp comment "App HTTP alt"

# ── Integración Wazuh (si hay manager) ──────────────────────────
if [[ -n "$WAZUH_MANAGER" ]]; then
    ufw allow out to "$WAZUH_MANAGER" port 1514 proto tcp comment "Wazuh agent"
    ufw allow out to "$WAZUH_MANAGER" port 1515 proto tcp comment "Wazuh enrollment"
    ok "Wazuh Manager: $WAZUH_MANAGER permitido"
fi

# ── Protección contra escaneos ───────────────────────────────────
info "Configurando protección contra escaneos..."
# Rate limiting en SSH
ufw limit "$SSH_PORT"/tcp comment "SSH rate limit"

# ── Habilitar logging ────────────────────────────────────────────
ufw logging on
ufw logging medium
ok "Logging UFW habilitado"

# ── Habilitar firewall ───────────────────────────────────────────
info "Habilitando UFW..."
ufw --force enable
ok "UFW habilitado"

# ── Resumen ──────────────────────────────────────────────────────
echo ""
info "=== ESTADO FINAL ==="
ufw status verbose
echo ""
info "Comandos útiles:"
echo "  ufw status verbose          # Ver todas las reglas"
echo "  ufw status numbered         # Ver reglas numeradas"
echo "  ufw delete NUMBER           # Eliminar regla por número"
echo "  ufw allow from IP to any    # Permitir IP específica"
echo "  tail -f /var/log/ufw.log    # Ver logs en tiempo real"
