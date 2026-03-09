#!/usr/bin/env bash
set -euo pipefail

echo "=============================================================="
echo " Setting up Vulnerability Management environment (2026 style)"
echo "=============================================================="

if ! command -v sudo >/dev/null 2>&1; then
    echo "Error: sudo is required" >&2
    exit 1
fi

echo "[+] Updating system..."
sudo apt update -y && sudo apt upgrade -y

echo "[+] Installing core tools..."
sudo apt install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget

echo "[+] Installing Greenbone Community Edition (GVM / OpenVAS successor)..."
sudo apt install -y gvm

echo "[+] Running automatic setup (creates admin user, downloads feeds, etc.)..."
sudo gvm-setup
# This usually prints the admin password at the end – capture or note it

echo "[+] Verifying setup..."
sudo gvm-check-setup

echo "[+] Starting services..."
sudo gvm-start

echo ""
echo "Environment ready!"
echo "→ Access Greenbone Security Assistant (GSA) web UI usually at: https://127.0.0.1:9392"
echo "→ Default credentials after gvm-setup: admin / (password printed above)"
echo "→ You may need to wait 5-15 min for initial feed sync to complete"
echo ""
echo "Optional: cve-search (local CVE database & search)"
read -p "Install cve-search too? (y/N): " install_cve
if [[ "$install_cve" =~ ^[Yy]$ ]]; then
    git clone https://github.com/cve-search/cve-search.git
    cd cve-search
    pip3 install --user -r requirements.txt
    ./sbin/db_mgmt_json.py -p   # populate CVE data (takes time)
    echo "cve-search installed. Run 'python3 bin/search.py -h' to start using it."
fi

echo "Done."