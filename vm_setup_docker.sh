#!/usr/bin/env bash
set -euo pipefail

echo "=============================================================="
echo " Setting up Vulnerability Management environment via Docker"
echo "           (Recommended for Ubuntu 22.04 / 24.04 in 2026)   "
echo "=============================================================="

if ! command -v sudo >/dev/null 2>&1; then
    echo "Error: sudo is required" >&2
    exit 1
fi

echo "[+] Updating system & installing prerequisites..."
sudo apt update -y && sudo apt upgrade -y
sudo apt install -y \
    python3 \
    python3-pip \
    git \
    curl \
    ca-certificates \
    gnupg

echo "[+] Installing Docker & docker compose plugin..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update -y
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[+] Adding current user to docker group (logout/login needed later)..."
sudo usermod -aG docker "$USER"

# Popular maintained GVM Docker compose stack (2025–2026 style)
echo "[+] Setting up Greenbone Community Edition via docker-compose..."
mkdir -p ~/gvm-docker && cd ~/gvm-docker

cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
  postgresql:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: gvm
      POSTGRES_PASSWORD: gvm
      POSTGRES_DB: gvmd
    volumes:
      - pgdata:/var/lib/postgresql/data
  gvmd:
    image: greenbone/gvmd:stable
    restart: unless-stopped
    depends_on:
      - redis
      - postgresql
    environment:
      - POSTGRES_HOST=postgresql
    volumes:
      - gvmd-data:/var/lib/gvm
  openvas-scanner:
    image: greenbone/openvas-scanner:stable
    restart: unless-stopped
    depends_on:
      - redis
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - openvas-data:/var/lib/openvas
  gsad:
    image: greenbone/gsad:stable
    restart: unless-stopped
    depends_on:
      - gvmd
    ports:
      - "9392:9392"
    volumes:
      - gsad-data:/var/lib/gsad
volumes:
  pgdata:
  gvmd-data:
  openvas-data:
  gsad-data:
EOF

echo "[+] Pulling images and starting stack..."
docker compose pull
docker compose up -d

echo ""
echo "Waiting ~2-5 minutes for initial setup and feed sync..."
sleep 120

echo "[+] Creating admin user (change password immediately after login!)"
docker compose exec -u gvmd gvmd --create-user=admin --password=admin123 --role=Admin

echo ""
echo "Environment ready!"
echo "→ Open browser → https://localhost:9392  (accept self-signed cert)"
echo "→ Login: admin / admin123   → change password right away"
echo "→ Feed sync may take 10–60 min on first run (check container logs)"
echo ""
echo "To stop:    cd ~/gvm-docker && docker compose down"
echo "To update:  docker compose pull && docker compose up -d"
echo ""

# Optional cve-search (non-Docker version)
read -p "Also install standalone cve-search tool? (y/N): " install_cve
if [[ "$install_cve" =~ ^[Yy]$ ]]; then
    git clone https://github.com/cve-search/cve-search.git
    cd cve-search
    pip3 install --user -r requirements.txt
    ./sbin/db_mgmt_json.py -p
    echo "cve-search ready. Use bin/search.py or start the web UI with python3 web/index.py"
fi

echo "All done."