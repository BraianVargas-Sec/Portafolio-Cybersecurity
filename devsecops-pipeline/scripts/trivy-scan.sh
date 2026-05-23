#!/bin/bash
# trivy-scan.sh
# Escaneo local de imágenes Docker y filesystem con Trivy
# Autor: briamrlz82

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

IMAGE="${1:-}"
SEVERITY="${2:-CRITICAL,HIGH}"

# ── Verificar que Trivy está instalado ──────────────────────────
if ! command -v trivy &>/dev/null; then
    info "Instalando Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
fi

if [[ -z "$IMAGE" ]]; then
    # Escanear filesystem si no se especifica imagen
    info "=== Trivy — Escaneo de dependencias (filesystem) ==="
    trivy fs \
        --severity "$SEVERITY" \
        --exit-code 1 \
        --ignore-unfixed \
        .
else
    # Escanear imagen Docker
    info "=== Trivy — Escaneo de imagen: $IMAGE ==="
    trivy image \
        --severity "$SEVERITY" \
        --exit-code 1 \
        --ignore-unfixed \
        "$IMAGE"
fi

if [[ $? -eq 0 ]]; then
    ok "Sin CVEs críticos encontrados"
else
    fail "CVEs encontrados — revisar antes de continuar"
    exit 1
fi
