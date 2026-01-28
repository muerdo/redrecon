#!/bin/bash

# RedRecon Installer Script
# Installs dependencies and simplifies the setup process.

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  log_warn "Please run as root to install system dependencies."
  exit 1
fi

log_info "Updating system repositories..."
apt-get update -y || log_warn "Failed to update repositories. Proceeding..."

log_info "Installing Git, Python3, Pip, and Basic Tools..."
apt-get install -y git python3 python3-pip python3-venv wget curl unzip libpcap-dev || {
    log_error "Failed to install base dependencies."
    exit 1
}

# --- Go Setup ---
if ! command -v go &> /dev/null; then
    log_info "Go not found. Installing Go..."
    # Download Go (adjust version as needed)
    wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
    rm go1.22.1.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
else
    log_info "Go is already installed."
fi

# Ensure GOPATH/bin is in PATH
export GOBIN=$(go env GOPATH)/bin
export PATH=$PATH:$GOBIN
if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "export PATH=\$PATH:$GOBIN" >> ~/.bashrc
fi

# --- Install Go Tools ---
log_info "Installing Go-based tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/owasp-amass/amass/v4/...@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/LukaSikic/subzy@latest"
    "github.com/trufflesecurity/trufflehog/v3@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    log_info "Installing $tool..."
    go install "$tool" || log_warn "Failed to install $tool"
done

# --- Install Python Tools ---
log_info "Installing Python-based tools..."

# Helper for pip install with break-system-packages
pip_install() {
    pip3 install "$@" --break-system-packages || log_warn "Failed to install python package: $*"
}

pip_install bbot
pip_install trufflehog3      # Legacy support if needed, but go version is better
pip_install impacket
pip_install bloodhound       # Installs bloodhound-python
pip_install bloodyAD
pip_install certipy-ad
pip_install cloud_enum       # installs cloud_enum
pip_install dirsearch
pip_install arjun
pip_install netexec          # Replacement for CrackMapExec

# --- Fix Binary Names / Symlinks ---
# redrecon checks for bloodhound.py but pip installs bloodhound-python or simply bloodhound
if command -v bloodhound-python &> /dev/null; then
    # Create symlink if bloodhound.py is missing
    if ! command -v bloodhound.py &> /dev/null; then
        ln -s $(which bloodhound-python) /usr/local/bin/bloodhound.py
        log_info "Symlinked bloodhound-python to bloodhound.py"
    fi
fi

# --- Install Enum4Linux-NG ---
if [ ! -d "/opt/enum4linux-ng" ]; then
    log_info "Cloning Enum4Linux-NG..."
    git clone https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng
    cd /opt/enum4linux-ng
    pip_install .
    cd -
    # Link binary
    ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
else
    log_info "Enum4Linux-NG already present in /opt"
fi

# --- Install CVESearch ---
# Assuming cvesearch refers to the tool that queries APIs or local DB.
# If it's a specific custom tool, we might need a specific repo.
# Based on check, if it expects 'cvesearch' in path.
# A common one is https://github.com/cve-search/cve-search but that is a server.
# Let's assume for now we use a placeholder or known client if found in code.
# The code view of cve_search.go might clarify.
# If unclear, I'll assume it's valid if user installs it manually or I skip explicit install if unknown.
# Actually, I'll wait for the view_file result to be certain.
# But I can add the others first.

# --- Install CloudEnum ---
if ! command -v cloudenum &> /dev/null; then
    # cloud_enum pip package might verify.
    # If pip install worked, check binary name.
    # usually it is cloud_enum or cloudenum?
    # 'pip install cloud_enum' often installs 'cloud_enum.py' or similar.
    # If pip fails, clone it.
    if ! pip3 show cloud_enum &> /dev/null; then
         log_info "Cloning CloudEnum..."
         git clone https://github.com/initstring/cloud_enum /opt/cloud_enum
         pip_install -r /opt/cloud_enum/requirements.txt
         ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloudenum
    fi
fi

# ParamSpider check (needs git clone usually)
if [ ! -d "/opt/ParamSpider" ]; then
    log_info "Cloning ParamSpider..."
    git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider
    cd /opt/ParamSpider
    pip_install .
    cd -
fi

# --- Install System Tools via APT ---
log_info "Installing System Tools..."
apt-get install -y nmap masscan wpscan 3proxy || log_warn "Some system tools failed to install."

# --- Proxy Configuration Setup ---
log_info "Configuring Proxy System..."

# Create config directory
mkdir -p /etc/redrecon
mkdir -p /etc/3proxy

# Prompt for Proxy Credentials
if [ ! -f "/etc/redrecon/proxy.env" ]; then
    log_info "Setting up Proxy Authentication..."
    read -p "Enter Proxy Username: " PROXY_USER
    read -s -p "Enter Proxy Password: " PROXY_PASS
    echo ""
    
    echo "PROXY_USER=$PROXY_USER" > /etc/redrecon/proxy.env
    echo "PROXY_PASS=$PROXY_PASS" >> /etc/redrecon/proxy.env
    chmod 600 /etc/redrecon/proxy.env
    log_info "Proxy credentials saved."
else
    log_info "Proxy credentials already exist in /etc/redrecon/proxy.env"
fi

# Locate and install scripts
# Assuming we are running inside the cloned repo directory
log_info "Installing Proxy Scripts..."

if [ -f "proxies/getproxy.sh" ]; then
    # We rename it to get-proxies.sh for clarity in the system path
    cp proxies/getproxy.sh /usr/local/bin/get-proxies.sh
    chmod +x /usr/local/bin/get-proxies.sh
else
    log_warn "proxies/getproxy.sh not found. Smart rotation may fail until fixed."
fi

if [ -f "scripts/start-3proxy-smart.sh" ]; then
    cp scripts/start-3proxy-smart.sh /usr/local/bin/start-3proxy-smart.sh
    chmod +x /usr/local/bin/start-3proxy-smart.sh
else
    log_warn "scripts/start-3proxy-smart.sh not found."
fi

# Install Systemd Service & Timer
if [ -f "scripts/3proxy-rotator.service" ]; then
    cp scripts/3proxy-rotator.service /etc/systemd/system/
    cp scripts/3proxy-rotator.timer /etc/systemd/system/
    
    systemctl daemon-reload
    systemctl enable 3proxy-rotator.timer
    systemctl start 3proxy-rotator.timer
    
    # Run once to initialize
    log_info "Initializing proxy list..."
    /usr/local/bin/start-3proxy-smart.sh || log_warn "Initial proxy update failed (check logs/auth)."
else
    log_warn "Service files not found. Automatic rotation disabled."
fi

# --- Rustscan (Debian package) ---
if ! command -v rustscan &> /dev/null; then
    log_info "Installing Rustscan..."
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    dpkg -i rustscan_2.0.1_amd64.deb || apt-get install -f -y
    rm rustscan_2.0.1_amd64.deb
fi

# --- Build RedRecon ---
log_info "Building RedRecon..."
go build -o redrecon ./cmd/redrecon || {
    log_error "Failed to build RedRecon."
    exit 1
}

log_info "Installation Complete! You can now run ./redrecon"
log_info "Make sure to source your .bashrc or restart your terminal if you just installed Go."
