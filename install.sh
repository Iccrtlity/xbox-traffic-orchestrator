#!/usr/bin/env bash
# ===========================================================================
# Xbox Screen-Time Orchestrator – Installer
# ===========================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

echo ""
echo "============================================="
echo "  Xbox Screen-Time Orchestrator – Installer"
echo "============================================="
echo ""

# ── 1. Check Docker ──────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    error "Docker is not installed."
    echo "  Install it from: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    error "Docker Compose plugin is not available."
    echo "  Install it from: https://docs.docker.com/compose/install/"
    exit 1
fi

info "Docker found: $(docker --version)"
info "Compose found: $(docker compose version --short)"
echo ""

# ── 2. Collect AdGuard Home credentials ──────────────────────────────
read -rp "AdGuard Home URL  [http://dns-server:80]: " ADGUARD_URL
ADGUARD_URL="${ADGUARD_URL:-http://dns-server:80}"

read -rp "AdGuard Home username              [admin]: " ADGUARD_USER
ADGUARD_USER="${ADGUARD_USER:-admin}"

read -rsp "AdGuard Home password                       : " ADGUARD_PASS
echo ""

# ── 3. Write .env ────────────────────────────────────────────────────
cat > .env <<EOF
ADGUARD_URL=${ADGUARD_URL}
ADGUARD_USER=${ADGUARD_USER}
ADGUARD_PASS=${ADGUARD_PASS}
EOF
chmod 600 .env
info ".env created successfully."

# ── 4. Ensure config.yaml exists ─────────────────────────────────────
if [ ! -f config.yaml ]; then
    warn "config.yaml not found – copying defaults from install template."
    cat > config.yaml <<'YAML'
adguard_url: "http://dns-server:80"
adguard_user: "admin"
adguard_pass: ""

xbox_domain:
  - "device.auth.xboxlive.com"
  - "title.auth.xboxlive.com"
  - "xsts.auth.xboxlive.com"
  - "def.auth.xboxlive.com"
  - "title.mgt.xboxlive.com"
  - "family.microsoft.com"
  - "familysafety.microsoft.com"
  - "presence.xboxlive.com"
  - "userpresence.xboxlive.com"
  - "activity.windows.com"
  - "edge.activity.windows.com"
  - "settings-win.data.microsoft.com"
  - "v10.events.data.microsoft.com"
  - "v20.events.data.microsoft.com"

bypass_duration: 3600
poll_interval: 30
xbox_client_ip: ""
startup_timeout: 120
YAML
    info "config.yaml created with defaults."
else
    info "config.yaml already exists – keeping current file."
fi

# ── 5. Build & start ─────────────────────────────────────────────────
echo ""
info "Building and starting services…"
docker compose up -d --build

echo ""
echo "============================================="
echo "  Installation complete!"
echo "============================================="
echo ""
info "Edit config.yaml to customise Xbox domains, bypass duration, etc."
info "Then restart with:  docker compose restart"
echo ""
