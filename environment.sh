#!/usr/bin/env bash
# ███████╗██╗ ██╗██╗███╗   ██╗ ██████╗ ██████╗ ███████╗
# ██╔════╝██║ ██╔╝██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝
# ███████╗█████╔╝ ██║██╔██╗ ██║██║  ███╗██║  ██║█████╗  
# ╚════██║██╔═██╗ ██║██║╚██╗██║██║   ██║██║  ██║██╔══╝  
# ███████║██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝███████╗
# ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝
# Skynode Security Scan Environment Builder
# Version: 7.0 (2026 Edition - Enhanced)
# Author: Security Automation Team (Refined)
# License: MIT
# ===========================================================

set -euo pipefail
IFS=$'\n\t'

# ====================[ CONFIGURATION ]====================
readonly SCRIPT_VERSION="7.0"
readonly MIN_PYTHON_VERSION="3.10"
readonly MIN_BASH_VERSION="5.0"
readonly SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S%3N)
readonly DATE_STAMP=$(date +%Y-%m-%d)
readonly DATETIME_STAMP=$(date +"%Y-%m-%d %H:%M:%S.%3N")

# ====================[ PATHS ]====================
readonly BASE_CONFIG_DIR="${HOME}/.config/skynode"
readonly BASE_DATA_DIR="${HOME}/.local/share/skynode"
readonly BASE_CACHE_DIR="${HOME}/.cache/skynode"
readonly BASE_LOG_DIR="${HOME}/.local/state/skynode/logs"

readonly LOG_DIR="${BASE_LOG_DIR}"
readonly CONFIG_DIR="${BASE_CONFIG_DIR}"
readonly TEMPLATE_DIR="${BASE_CONFIG_DIR}/templates"
readonly CACHE_DIR="${BASE_CACHE_DIR}"
readonly PROFILES_DIR="${BASE_CONFIG_DIR}/profiles"
readonly PLUGINS_DIR="${BASE_CONFIG_DIR}/plugins"

readonly LOG_FILE="${LOG_DIR}/${TIMESTAMP}_setup.log"
readonly CONFIG_FILE="${CONFIG_DIR}/skynode.conf"
readonly PROFILES_FILE="${PROFILES_DIR}/profiles.conf"
readonly ERROR_LOG="${LOG_DIR}/errors.log"
readonly MAX_LOGS=20
readonly MAX_LOG_AGE_DAYS=30

# ====================[ COLOR CODES ]====================
if [[ -t 1 ]]; then
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly UNDERLINE='\033[4m'
    readonly BLINK='\033[5m'
    readonly REVERSE='\033[7m'
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly PURPLE='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly ORANGE='\033[0;33m'
    readonly MAGENTA='\033[0;35m'
    readonly NC='\033[0m'
else
    readonly BOLD='' DIM='' UNDERLINE='' BLINK='' REVERSE=''
    readonly RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' ORANGE='' MAGENTA='' NC=''
fi

# ====================[ STATE VARIABLES ]====================
declare -A CONFIG=(
    [debug]=false
    [force]=false
    [verbose]=false
    [quiet]=false
    [interactive]=true
    [system_name]=""
    [base_dir]="$(pwd)"
    [profile]="default"
    [skip_venv]=false
    [skip_updates]=false
    [export_pdf]=false
    [generate_report]=false
    [init_git]=false
    [create_docker]=false
    [backup_existing]=false
    [encrypt_notes]=false
    [json_logs]=false
    [auto_install_tools]=false
    [cloud_setup]=""
    [use_poetry]=false
    [test_mode]=false
    [dry_run]=false
    [git_remote]=""
    [container_runtime]="docker"
    [report_format]="html,md"
)

declare -a TAGS=()
declare -a EXCLUDE_DIRS=()
declare -a CUSTOM_TOOLS=()
declare -a INCLUDED_TOOLS=()
declare -a PYTHON_PACKAGES=()

# ====================[ FUNCTION: LOGGING ]====================
init_logging() {
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$CACHE_DIR" "$TEMPLATE_DIR" "$PROFILES_DIR" "$PLUGINS_DIR" || {
        echo "FATAL: Cannot create directories" >&2
        exit 1
    }
    
    # Rotate old logs
    find "$LOG_DIR" -name "*.log" -type f -mtime +${MAX_LOG_AGE_DAYS} -delete
    
    # Keep only MAX_LOGS most recent
    local log_count
    log_count=$(ls -1 "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    if [[ $log_count -gt $MAX_LOGS ]]; then
        ls -t "$LOG_DIR"/*.log | tail -n +$((MAX_LOGS + 1)) | xargs rm -f
    fi
    
    exec 3>&1 4>&2
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    log "Skynode Security Environment v${SCRIPT_VERSION}" "INFO"
    log "Started at: ${DATETIME_STAMP}" "INFO"
    log "User: ${USER}" "DEBUG"
    log "Working directory: $(pwd)" "DEBUG"
}

log() {
    local msg="$1"
    local level="${2:-INFO}"
    local timestamp=$(date +"%H:%M:%S.%3N")
    
    if [[ "${CONFIG[json_logs]}" == true ]]; then
        printf '{"timestamp":"%s","level":"%s","message":"%s"}\n' \
            "$timestamp" "$level" "$msg" >> "${LOG_FILE}.json"
    fi
    
    case "$level" in
        "ERROR")   echo -e "${RED}[${timestamp}] ERROR: ${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        "WARN")    echo -e "${YELLOW}[${timestamp}] WARN: ${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        "SUCCESS") echo -e "${GREEN}[${timestamp}] ✓ ${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        "INFO")    [[ "${CONFIG[quiet]}" == false ]] && echo -e "${CYAN}[${timestamp}] INFO: ${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        "DEBUG")   [[ "${CONFIG[debug]}" == true ]] && echo -e "${PURPLE}[${timestamp}] DEBUG: ${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        "HEADER")  echo -e "${BOLD}${BLUE}${msg}${NC}" | tee -a "$LOG_FILE" >&3 ;;
        *)         echo -e "[${timestamp}] ${msg}" | tee -a "$LOG_FILE" >&3 ;;
    esac
}

error() {
    local msg="$1"
    local code="${2:-1}"
    log "$msg" "ERROR"
    echo -e "${RED}$msg${NC}" >&4
    return "$code"
}

warn() { log "$1" "WARN"; }
success() { log "$1" "SUCCESS"; }
debug() { log "$1" "DEBUG"; }

# ====================[ FUNCTION: CLEANUP ]====================
cleanup() {
    local exit_code=$?
    local end_time
    end_time=$(date +%s%3N)
    local duration=$((end_time - START_TIME))
    
    if [[ $exit_code -ne 0 ]]; then
        error "Script failed with exit code: $exit_code"
        error "Check log file: $LOG_FILE"
        
        # Generate error report
        {
            echo "Error Report"
            echo "============"
            echo "Timestamp: ${DATETIME_STAMP}"
            echo "Script: ${SCRIPT_NAME}"
            echo "Version: ${SCRIPT_VERSION}"
            echo "Exit Code: ${exit_code}"
            echo "Duration: ${duration}ms"
            echo ""
            echo "System Info:"
            echo "- OS: $(uname -a)"
            echo "- Bash: ${BASH_VERSION}"
            echo "- Python: $(python3 --version 2>&1 || echo 'Not found')"
            echo "- Memory: $(free -h 2>/dev/null || echo 'N/A')"
            echo "- Disk: $(df -h . 2>/dev/null || echo 'N/A')"
            echo ""
            echo "Last 50 log entries:"
            tail -50 "$LOG_FILE"
        } > "${LOG_DIR}/error_report_${TIMESTAMP}.txt"
    else
        success "Script completed successfully (${duration}ms)"
    fi
    
    exec 1>&3 2>&4
    exit "$exit_code"
}

trap cleanup EXIT INT TERM
START_TIME=$(date +%s%3N)

# ====================[ FUNCTION: ASCII ART ]====================
show_header() {
    if [[ "${CONFIG[quiet]}" == false ]]; then
        cat << 'EOF' >&3
${BOLD}${BLUE}
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║ ███████╗██╗ ██╗██╗███╗   ██╗ ██████╗ ██████╗ ███████╗             ║
║ ██╔════╝██║ ██╔╝██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝             ║
║ ███████╗█████╔╝ ██║██╔██╗ ██║██║  ███╗██║  ██║█████╗               ║
║ ╚════██║██╔═██╗ ██║██║╚██╗██║██║   ██║██║  ██║██╔══╝                ║
║ ███████║██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝███████╗             ║
║ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝             ║
║                                                                   ║
║ ${WHITE}SECURITY SCAN ENVIRONMENT BUILDER${BLUE}                               ║
║ ${CYAN}Version ${SCRIPT_VERSION} | 2026 Edition${BLUE}                       ║
╚═══════════════════════════════════════════════════════════════════╝
${NC}
EOF
    fi
}

# ====================[ FUNCTION: CONFIGURATION ]====================
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        debug "Loading configuration from: $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
    
    if [[ -f "$PROFILES_FILE" ]]; then
        debug "Loading profiles from: $PROFILES_FILE"
        # shellcheck source=/dev/null
        source "$PROFILES_FILE"
    else
        create_default_profiles
    fi
}

create_default_profiles() {
    cat > "$PROFILES_FILE" << 'EOF'
# Skynode Profiles Configuration v7.0
# Format: profile_name|description|directories|python_packages|tools

standard|Standard pentesting profile|recon/nmap,recon/dns,scanning,enumeration,exploitation,post-exploitation,reporting,tools|requests,httpx,python-nmap,colorama,tqdm|nmap,masscan,nc,nikto,gobuster

web|Web application testing|recon/web,scanning/web,enumeration/web,exploitation/web,reporting,tools|requests,httpx,beautifulsoup4,selenium,playwright|ffuf,nikto,sqlmap,xsstrike,wpscan

network|Network infrastructure|recon/network,scanning/ports,enumeration/services,exploitation/network,reporting|scapy,paramiko,netaddr|nmap,masscan,hydra,medusa,enum4linux

cloud|Cloud security|recon/cloud,scanning/cloud,enumeration/cloud,exploitation/cloud,reporting|boto3,google-cloud-sdk,azure-mgmt|awscli,gcloud,az,cloudsploit,prowler

container|Container security|recon/container,scanning/images,enumeration/k8s,exploitation/container,reporting|docker,kubernetes|trivy,grype,cosign,skopeo,kubectl

full|Complete toolkit|recon/all,scanning/all,enumeration/all,exploitation/all,post-exploitation/all,reporting,tools|all|all
EOF
    debug "Default profiles created"
}

# ====================[ FUNCTION: COMMAND LINE PARSING ]====================
parse_arguments() {
    local opts
    
    opts=$(getopt -o n:p:f,d,v,q,h \
        --long name:,path:,force,debug,verbose,quiet,non-interactive \
        --long profile:,tag:,exclude:,tool:,skip-venv,skip-updates \
        --long export-pdf,generate-report,init-git,create-docker,backup \
        --long encrypt-notes,json-logs,auto-install-tools,cloud-setup: \
        --long use-poetry,test-mode,git-remote:,dry-run,help,version \
        -n "$SCRIPT_NAME" -- "$@")
    
    eval set -- "$opts"
    
    while true; do
        case "$1" in
            -n|--name) CONFIG[system_name]="$2"; shift 2 ;;
            -p|--path) CONFIG[base_dir]="$2"; shift 2 ;;
            -f|--force) CONFIG[force]=true; shift ;;
            -d|--debug) CONFIG[debug]=true; CONFIG[verbose]=true; shift ;;
            -v|--verbose) CONFIG[verbose]=true; shift ;;
            -q|--quiet) CONFIG[quiet]=true; shift ;;
            --non-interactive) CONFIG[interactive]=false; shift ;;
            --profile) CONFIG[profile]="$2"; shift 2 ;;
            --tag) TAGS+=("$2"); shift 2 ;;
            --exclude) EXCLUDE_DIRS+=("$2"); shift 2 ;;
            --tool) CUSTOM_TOOLS+=("$2"); shift 2 ;;
            --skip-venv) CONFIG[skip_venv]=true; shift ;;
            --skip-updates) CONFIG[skip_updates]=true; shift ;;
            --export-pdf) CONFIG[export_pdf]=true; shift ;;
            --generate-report) CONFIG[generate_report]=true; shift ;;
            --init-git) CONFIG[init_git]=true; shift ;;
            --create-docker) CONFIG[create_docker]=true; shift ;;
            --backup) CONFIG[backup_existing]=true; shift ;;
            --encrypt-notes) CONFIG[encrypt_notes]=true; shift ;;
            --json-logs) CONFIG[json_logs]=true; shift ;;
            --auto-install-tools) CONFIG[auto_install_tools]=true; shift ;;
            --cloud-setup) CONFIG[cloud_setup]="$2"; shift 2 ;;
            --use-poetry) CONFIG[use_poetry]=true; shift ;;
            --test-mode) CONFIG[test_mode]=true; shift ;;
            --git-remote) CONFIG[git_remote]="$2"; shift 2 ;;
            --dry-run) CONFIG[dry_run]=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            --version) echo "Skynode v${SCRIPT_VERSION}"; exit 0 ;;
            --) shift; break ;;
            *) error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
}

# ====================[ FUNCTION: SHOW HELP ]====================
show_help() {
    cat << EOF
${BOLD}Skynode Security Environment Builder v${SCRIPT_VERSION}${NC}

${UNDERLINE}Description:${NC}
  Creates a professional security testing environment with comprehensive
  directory structure, tool integration, and reporting capabilities.

${UNDERLINE}Usage:${NC}
  $SCRIPT_NAME [OPTIONS]

${UNDERLINE}Required:${NC}
  -n, --name NAME    Target system identifier (e.g., corp-dc-01)

${UNDERLINE}Directory:${NC}
  -p, --path DIR     Base directory (default: current)
  --exclude DIR      Exclude directory from creation

${UNDERLINE}Behavior:${NC}
  -f, --force        Skip all prompts
  --non-interactive  Run without user interaction
  --backup          Backup existing directory
  --dry-run         Simulate actions without executing

${UNDERLINE}Output:${NC}
  -q, --quiet        Suppress informational messages
  -v, --verbose      Show detailed output
  -d, --debug        Show debug information
  --json-logs       Log in JSON format
  --export-pdf      Generate PDF summary
  --generate-report Create HTML/MD report

${UNDERLINE}Environment:${NC}
  --profile NAME    Use specific profile (standard, web, network, cloud, container, full)
  --tag TAG         Add metadata tag (can be repeated)
  --tool NAME       Include additional tool (git:repo or pip:pkg)
  --skip-venv       Skip Python virtual environment
  --skip-updates    Skip system updates
  --auto-install-tools Attempt to install missing tools
  --use-poetry      Use Poetry instead of venv

${UNDERLINE}Features:${NC}
  --init-git        Initialize git repository
  --git-remote URL  Push to remote git repo
  --create-docker   Create Dockerfile
  --encrypt-notes   Enable encrypted notes
  --cloud-setup TYPE Setup cloud CLI (aws|gcp|azure)
  --test-mode       Run self-tests after setup

${UNDERLINE}Examples:${NC}
  $SCRIPT_NAME --name webserver01 --profile web --auto-install-tools
  $SCRIPT_NAME -n pentest01 -p /opt/assessments --profile full --init-git
  $SCRIPT_NAME -n cloud-assessment --cloud-setup aws --encrypt-notes
  $SCRIPT_NAME --name test --dry-run --verbose

${UNDERLINE}Configuration:${NC}
  Config: ${CONFIG_FILE}
  Profiles: ${PROFILES_FILE}
  Logs: ${LOG_DIR}
EOF
}

# ====================[ FUNCTION: SYSTEM VALIDATION ]====================
validate_system() {
    log "Validating system requirements..." "INFO"
    
    # Check Bash version
    if (( BASH_VERSINFO[0] < 5 )); then
        error "Bash 5.0+ required (found ${BASH_VERSION})" || return 1
    fi
    
    # Check Python version
    if command -v python3 &>/dev/null; then
        local py_version
        py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if (( $(echo "$py_version < $MIN_PYTHON_VERSION" | bc -l 2>/dev/null || echo 1) )); then
            warn "Python ${MIN_PYTHON_VERSION}+ recommended (found ${py_version})"
        fi
    else
        error "Python 3 not found" || return 1
    fi
    
    # Check disk space
    local available_space
    available_space=$(df -k "${CONFIG[base_dir]}" | awk 'NR==2 {print $4}')
    if (( available_space < 1048576 )); then
        warn "Less than 1GB free space (${available_space}KB)"
        if [[ "${CONFIG[force]}" != true ]] && [[ "${CONFIG[interactive]}" == true ]]; then
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && return 1
        fi
    fi
    
    # Check internet connectivity
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        warn "No internet connectivity detected"
    fi
    
    check_prerequisites
    return 0
}

# ====================[ FUNCTION: CHECK PREREQUISITES ]====================
check_prerequisites() {
    log "Checking prerequisites..." "INFO"
    
    local required_tools=(python3 curl wget git)
    local optional_tools=(nmap masscan nikto gobuster hydra john sqlmap nuclei trufflehog semgrep)
    local missing_required=()
    local missing_optional=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
        fi
    done
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_optional+=("$tool")
        fi
    done
    
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_required[*]}" || return 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]] && [[ "${CONFIG[auto_install_tools]}" == true ]]; then
        log "Attempting to install missing tools..." "INFO"
        if command -v apt-get &>/dev/null; then
            sudo apt-get update && sudo apt-get install -y "${missing_optional[@]}" || warn "Auto-install failed"
        elif command -v yum &>/dev/null; then
            sudo yum install -y "${missing_optional[@]}" || warn "Auto-install failed"
        fi
    fi
    
    success "All required tools present"
}

# ====================[ FUNCTION: SANITIZE NAME ]====================
sanitize_name() {
    local name="$1"
    
    name=$(echo "$name" | xargs | tr '[:space:]' '_' | sed 's/[^a-zA-Z0-9._-]/_/g')
    name=$(echo "$name" | sed 's/__*/_/g; s/^_//; s/_$//' | tr '[:upper:]' '[:lower:]')
    
    if [[ -z "$name" ]]; then
        error "System name cannot be empty" || return 1
    fi
    
    echo "$name"
}

# ====================[ FUNCTION: LOAD PROFILE ]====================
load_profile() {
    local profile_name="${CONFIG[profile]}"
    local profile_line
    
    if [[ ! -f "$PROFILES_FILE" ]]; then
        warn "Profiles file not found, using defaults"
        return 0
    fi
    
    profile_line=$(grep "^${profile_name}|" "$PROFILES_FILE" | head -1)
    
    if [[ -z "$profile_line" ]]; then
        warn "Profile '$profile_name' not found, falling back to standard"
        profile_line=$(grep "^standard|" "$PROFILES_FILE" | head -1)
        CONFIG[profile]="standard"
    fi
    
    if [[ -n "$profile_line" ]]; then
        IFS='|' read -r _ _ dirs pkgs tools <<< "$profile_line"
        
        [[ -n "$dirs" ]] && DIRECTORIES=(${dirs//,/ })
        [[ -n "$pkgs" ]] && PYTHON_PACKAGES=(${pkgs//,/ })
        [[ -n "$tools" ]] && INCLUDED_TOOLS=(${tools//,/ })
        
        debug "Loaded profile: ${CONFIG[profile]}"
    fi
}

# ====================[ FUNCTION: CREATE DIRECTORY STRUCTURE ]====================
create_directory_structure() {
    local root="$1"
    
    log "Creating directory structure..." "INFO"
    
    mkdir -p "$root"
    
    # Default directories if none defined
    if [[ ${#DIRECTORIES[@]} -eq 0 ]]; then
        DIRECTORIES=(
            "reconnaissance/nmap" "reconnaissance/dns" "reconnaissance/web"
            "scanning/ports" "scanning/services" "scanning/vulns"
            "enumeration/users" "enumeration/shares" "enumeration/services"
            "exploitation/payloads" "exploitation/msf" "exploitation/manual"
            "post-exploitation/loot" "post-exploitation/creds" "post-exploitation/persistence"
            "reporting/findings" "reporting/evidence" "reporting/screenshots" "reporting/final"
            "tools/custom" "tools/scripts"
            "notes/interviews" "notes/observations"
            "temp/downloads" "temp/uploads"
        )
    fi
    
    # Create directories
    for dir in "${DIRECTORIES[@]}"; do
        local exclude=false
        for excluded in "${EXCLUDE_DIRS[@]}"; do
            if [[ "$dir" == "$excluded"* ]]; then
                exclude=true
                break
            fi
        done
        
        if [[ "$exclude" == false ]]; then
            mkdir -p "$root/$dir"
            debug "Created: $dir"
        fi
    done
    
    # Create tag directories
    for tag in "${TAGS[@]}"; do
        mkdir -p "$root/tags/$tag"
    done
    
    # Set permissions
    find "$root" -type d -exec chmod 750 {} \;
    find "$root" -type f -exec chmod 640 {} \; 2>/dev/null || true
    
    success "Directory structure created"
}

# ====================[ FUNCTION: CREATE VIRTUAL ENVIRONMENT ]====================
create_virtual_environment() {
    local root="$1"
    local venv_path="$root/.venv"
    
    if [[ "${CONFIG[skip_venv]}" == true ]]; then
        log "Skipping virtual environment" "INFO"
        return 0
    fi
    
    log "Creating Python environment..." "INFO"
    
    if [[ "${CONFIG[use_poetry]}" == true ]]; then
        if ! command -v poetry &>/dev/null; then
            warn "Poetry not found, installing..."
            curl -sSL https://install.python-poetry.org | python3 - || error "Poetry install failed"
        fi
        
        cd "$root" || return
        poetry init --name "${CONFIG[system_name]}" --description "Security assessment environment" --no-interaction
        
        if [[ ${#PYTHON_PACKAGES[@]} -gt 0 ]]; then
            poetry add "${PYTHON_PACKAGES[@]}"
        fi
        
        poetry install
        cd - >/dev/null || return
        
        cat > "$root/activate.sh" << 'EOF'
#!/bin/bash
poetry shell
EOF
    else
        if [[ -d "$venv_path" ]] && [[ "${CONFIG[force]}" == true ]]; then
            rm -rf "$venv_path"
        fi
        
        python3 -m venv "$venv_path"
        
        # shellcheck disable=SC1091
        source "$venv_path/bin/activate" || error "Failed to activate virtual environment"
        
        pip install --upgrade pip setuptools wheel --quiet
        
        if [[ ${#PYTHON_PACKAGES[@]} -gt 0 ]]; then
            log "Installing Python packages..." "INFO"
            pip install "${PYTHON_PACKAGES[@]}"
        fi
        
        pip freeze > "$root/requirements.txt"
        deactivate
        
        cat > "$root/activate.sh" << 'EOF'
#!/bin/bash
source .venv/bin/activate
EOF
    fi
    
    chmod +x "$root/activate.sh"
    success "Python environment created"
}

# ====================[ FUNCTION: CREATE METADATA ]====================
create_metadata() {
    local root="$1"
    local target="$2"
    
    log "Creating metadata files..." "INFO"
    
    # Create README
    cat > "$root/README.md" << EOF
# Security Assessment: ${target}

## Overview
- **Target:** ${target}
- **Date:** ${DATE_STAMP}
- **Assessor:** ${USER}
- **Profile:** ${CONFIG[profile]}
- **Workspace:** \`${root}\`

## Scope
Security assessment of **${target}** using Skynode v${SCRIPT_VERSION}.

## Tags
$(for tag in "${TAGS[@]}"; do echo "- ${tag}"; done)

## Directory Structure
\`\`\`
$(find "$root" -type d -maxdepth 3 | sort | sed "s|^$root/||" 2>/dev/null || echo "No directories yet")
\`\`\`

## Quick Start
\`\`\`bash
cd ${root}
source activate.sh
# Begin assessment
\`\`\`

## Tools
- Python Environment: \`source activate.sh\`
- Requirements: \`requirements.txt\` or \`pyproject.toml\`
$(for tool in "${INCLUDED_TOOLS[@]}"; do echo "- ${tool}"; done)

## Notes
- Document findings in \`reporting/findings/\`
- Store evidence in \`reporting/evidence/\`
- Screenshots go in \`reporting/screenshots/\`
- Custom tools in \`tools/custom/\`

---
*Created with Skynode Security Environment Builder v${SCRIPT_VERSION}*
EOF
    
    # Create .gitignore
    cat > "$root/.gitignore" << 'EOF'
# Python
__pycache__/
*.py[cod]
*.so
.Python
.venv/
env/
venv/
*.egg-info/
dist/
build/
poetry.lock

# Temp
tmp/
temp/
*.tmp
*.log
*.cache
*.pid

# OS
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# Security
*.pem
*.key
*.crt
*.p12
*.pfx
creds/
loot/

# Large
*.pcap
*.pcapng
*.mem
*.vmem
*.raw
*.dd
*.img

# Cloud
.aws/
.gcloud/
.azure/
EOF
    
    # Create workspace.json
    {
        echo "{"
        echo "  \"metadata\": {"
        echo "    \"version\": \"${SCRIPT_VERSION}\","
        echo "    \"created\": \"$(date --iso-8601=seconds)\","
        echo "    \"created_by\": \"${USER}\""
        echo "  },"
        echo "  \"target\": {"
        echo "    \"name\": \"${target}\","
        echo "    \"tags\": [$(printf '"%s",' "${TAGS[@]}" | sed 's/,$//')],"
        echo "    \"profile\": \"${CONFIG[profile]}\""
        echo "  }"
        echo "}"
    } > "$root/workspace.json"
    
    success "Metadata files created"
}

# ====================[ FUNCTION: CREATE DOCKERFILE ]====================
create_dockerfile() {
    local root="$1"
    
    cat > "$root/Dockerfile" << EOF
FROM kalilinux/kali-rolling:latest
LABEL maintainer="${USER}"
LABEL description="Security assessment environment for ${CONFIG[system_name]}"
LABEL version="${SCRIPT_VERSION}"

RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    nmap \\
    masscan \\
    nikto \\
    gobuster \\
    hydra \\
    john \\
    sqlmap \\
    metasploit-framework \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace

RUN python3 -m venv .venv && \\
    . .venv/bin/activate && \\
    pip install --upgrade pip && \\
    pip install -r requirements.txt 2>/dev/null || true

CMD ["/bin/bash"]
EOF
    
    debug "Dockerfile created"
}

# ====================[ FUNCTION: INIT GIT ]====================
init_git_repository() {
    local root="$1"
    
    if ! command -v git &>/dev/null; then
        warn "Git not found, skipping repository initialization"
        return 0
    fi
    
    cd "$root" || return
    
    git init --quiet
    git add README.md workspace.json .gitignore requirements.txt activate.sh 2>/dev/null || true
    git commit -m "Initial commit: Security assessment for ${CONFIG[system_name]}" --quiet
    
    if [[ -n "${CONFIG[git_remote]}" ]]; then
        git remote add origin "${CONFIG[git_remote]}"
        git push -u origin master || warn "Git push failed"
    fi
    
    cd - >/dev/null || return
    success "Git repository initialized"
}

# ====================[ FUNCTION: SETUP ENCRYPTION ]====================
setup_encryption() {
    local root="$1"
    
    if [[ "${CONFIG[encrypt_notes]}" != true ]]; then
        return 0
    fi
    
    log "Setting up encrypted notes..." "INFO"
    
    mkdir -p "$root/notes/encrypted"
    
    if command -v age &>/dev/null; then
        mkdir -p "$HOME/.age"
        if [[ ! -f "$HOME/.age/key.txt" ]]; then
            age-keygen -o "$HOME/.age/key.txt" 2>/dev/null
        fi
        
        local recipient
        recipient=$(age-keygen -y "$HOME/.age/key.txt" 2>/dev/null)
        
        cat > "$root/encrypt_notes.sh" << EOF
#!/bin/bash
NOTES_DIR="notes/encrypted"
RECIPIENT="$recipient"

case "\$1" in
    encrypt)
        for f in "\$NOTES_DIR"/*.txt; do
            [ -f "\$f" ] && age -r "\$RECIPIENT" "\$f" > "\$f.age" && rm "\$f"
        done
        ;;
    decrypt)
        for f in "\$NOTES_DIR"/*.age; do
            [ -f "\$f" ] && age -d "\$f" > "\${f%.age}" && rm "\$f"
        done
        ;;
    *)
        echo "Usage: \$0 {encrypt|decrypt}"
        exit 1
        ;;
esac
EOF
    else
        cat > "$root/encrypt_notes.sh" << 'EOF'
#!/bin/bash
NOTES_DIR="notes/encrypted"
GPG_RECIPIENT="${USER}"

case "$1" in
    encrypt)
        for f in "$NOTES_DIR"/*.txt; do
            [ -f "$f" ] && gpg --encrypt --recipient "$GPG_RECIPIENT" "$f"
        done
        ;;
    decrypt)
        for f in "$NOTES_DIR"/*.gpg; do
            [ -f "$f" ] && gpg --decrypt "$f" > "${f%.gpg}"
        done
        ;;
    *)
        echo "Usage: $0 {encrypt|decrypt}"
        exit 1
        ;;
esac
EOF
    fi
    
    chmod +x "$root/encrypt_notes.sh"
    success "Encryption setup complete"
}

# ====================[ FUNCTION: SETUP CLOUD ]====================
setup_cloud() {
    local root="$1"
    
    if [[ -z "${CONFIG[cloud_setup]}" ]]; then
        return 0
    fi
    
    log "Setting up cloud CLI for ${CONFIG[cloud_setup]}..." "INFO"
    
    mkdir -p "$root/cloud/${CONFIG[cloud_setup]}"
    
    case "${CONFIG[cloud_setup]}" in
        aws)
            if ! command -v aws &>/dev/null; then
                warn "AWS CLI not found"
                if [[ "${CONFIG[auto_install_tools]}" == true ]]; then
                    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
                    unzip -q awscliv2.zip
                    sudo ./aws/install
                    rm -rf awscliv2.zip aws
                fi
            fi
            ;;
        gcp)
            if ! command -v gcloud &>/dev/null && [[ "${CONFIG[auto_install_tools]}" == true ]]; then
                curl https://sdk.cloud.google.com | bash
            fi
            ;;
        azure)
            if ! command -v az &>/dev/null && [[ "${CONFIG[auto_install_tools]}" == true ]]; then
                curl -sL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
                sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli $(lsb_release -cs) main"
                sudo apt-get update && sudo apt-get install azure-cli
            fi
            ;;
        *)
            warn "Unknown cloud provider: ${CONFIG[cloud_setup]}"
            ;;
    esac
    
    success "Cloud setup complete"
}

# ====================[ FUNCTION: GENERATE REPORT ]====================
generate_report() {
    local root="$1"
    local target="$2"
    local report_dir="$root/reporting/final"
    
    log "Generating reports..." "INFO"
    
    mkdir -p "$report_dir"
    
    # HTML Report
    cat > "$report_dir/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment: ${target}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #333; }
        h2 { color: #666; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        pre { background: #fff; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <h2>Target: ${target}</h2>
    
    <table>
        <tr><th>Date</th><td>${DATE_STAMP}</td></tr>
        <tr><th>Assessor</th><td>${USER}</td></tr>
        <tr><th>Profile</th><td>${CONFIG[profile]}</td></tr>
        <tr><th>Workspace</th><td>${root}</td></tr>
    </table>
    
    <h3>Tags</h3>
    <ul>
        $(for tag in "${TAGS[@]}"; do echo "<li>${tag}</li>"; done)
    </ul>
    
    <h3>Directory Structure</h3>
    <pre>$(find "$root" -type d -maxdepth 3 | sort | sed "s|^$root/||" 2>/dev/null)</pre>
</body>
</html>
EOF
    
    # Copy README as Markdown report
    cp "$root/README.md" "$report_dir/report.md"
    
    success "Reports generated in $report_dir"
}

# ====================[ FUNCTION: EXPORT TO PDF ]====================
export_to_pdf() {
    local root="$1"
    
    if command -v pandoc &>/dev/null; then
        cd "$root" || return
        pandoc README.md -o "reporting/final/report.pdf" --pdf-engine=xelatex 2>/dev/null || \
        pandoc README.md -o "reporting/final/report.pdf" --pdf-engine=wkhtmltopdf 2>/dev/null
        cd - >/dev/null || return
        success "PDF exported"
    else
        warn "Pandoc not found, skipping PDF export"
    fi
}

# ====================[ FUNCTION: CREATE BACKUP ]====================
create_backup() {
    local original_dir="$1"
    local backup_dir="${original_dir}.backup.${TIMESTAMP}"
    
    if [[ -d "$original_dir" ]]; then
        log "Creating backup: $backup_dir" "INFO"
        cp -a "$original_dir" "$backup_dir"
        success "Backup created: $backup_dir"
    fi
}

# ====================[ FUNCTION: RUN TESTS ]====================
run_tests() {
    local root="$1"
    
    log "Running self-tests..." "INFO"
    
    # Test activation
    if [[ -f "$root/activate.sh" ]]; then
        bash -c "source $root/activate.sh" || warn "Activation test failed"
    fi
    
    # Test directory structure
    for dir in "${DIRECTORIES[@]}"; do
        if [[ ! -d "$root/$dir" ]]; then
            warn "Missing directory: $dir"
        fi
    done
    
    # Test encryption if enabled
    if [[ "${CONFIG[encrypt_notes]}" == true ]] && [[ -f "$root/encrypt_notes.sh" ]]; then
        echo "test" > "$root/notes/encrypted/test.txt"
        bash "$root/encrypt_notes.sh" encrypt
        bash "$root/encrypt_notes.sh" decrypt
        rm -f "$root/notes/encrypted/test"*
    fi
    
    success "Self-tests completed"
}

# ====================[ FUNCTION: SHOW SUMMARY ]====================
show_summary() {
    local root="$1"
    
    # Create symlink
    ln -sfn "$(basename "$root")" "${CONFIG[base_dir]}/latest_scan"
    
    cat << EOF >&3
${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}
${GREEN}║${NC} ${BOLD}ENVIRONMENT SETUP COMPLETE${NC} ${GREEN}║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${BOLD}Location:${NC} $root
${BOLD}Target:${NC} ${CONFIG[system_name]}
${BOLD}Profile:${NC} ${CONFIG[profile]}
${BOLD}Tags:${NC} $(IFS=,; echo "${TAGS[*]:-none}")
${BOLD}Log File:${NC} $LOG_FILE
${BOLD}Size:${NC} $(du -sh "$root" 2>/dev/null | cut -f1)
${BOLD}Quick Access:${NC}
  ${CYAN}→${NC} Activate: source $root/activate.sh
  ${CYAN}→${NC} README: cat $root/README.md
  ${CYAN}→${NC} Workspace: cd $root
  ${CYAN}→${NC} Symlink: ${CONFIG[base_dir]}/latest_scan
${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}
${BOLD}Happy Hunting!${NC} ${DIM}Skynode v${SCRIPT_VERSION}${NC}
EOF
}

# ====================[ MAIN ]====================
main() {
    init_logging
    show_header
    load_config
    
    parse_arguments "$@"
    
    # Get system name if not provided
    if [[ -z "${CONFIG[system_name]}" ]] && [[ "${CONFIG[interactive]}" == true ]]; then
        printf "${BLUE}Enter target system name: ${NC}"
        read -r CONFIG[system_name]
    fi
    
    if [[ -z "${CONFIG[system_name]}" ]]; then
        error "System name is required (use -n or --name)"
    fi
    
    CONFIG[system_name]=$(sanitize_name "${CONFIG[system_name]}") || exit 1
    
    # Build scan directory path
    local scan_dir="${CONFIG[base_dir]}/${CONFIG[system_name]}_${DATE_STAMP}"
    
    # Handle existing directory
    if [[ -d "$scan_dir" ]]; then
        if [[ "${CONFIG[backup_existing]}" == true ]]; then
            create_backup "$scan_dir"
            rm -rf "$scan_dir"
        elif [[ "${CONFIG[force]}" == true ]]; then
            rm -rf "$scan_dir"
        elif [[ "${CONFIG[interactive]}" == true ]]; then
            read -p "Directory exists. Delete? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                rm -rf "$scan_dir"
            else
                error "Aborted" 0
            fi
        else
            error "Directory exists: $scan_dir"
        fi
    fi
    
    # Dry run
    if [[ "${CONFIG[dry_run]}" == true ]]; then
        log "DRY RUN: Would create environment at $scan_dir" "INFO"
        show_summary "$scan_dir"
        exit 0
    fi
    
    # Validate system
    validate_system || exit 1
    
    # Load profile
    load_profile
    
    # Create environment
    create_directory_structure "$scan_dir"
    create_virtual_environment "$scan_dir"
    create_metadata "$scan_dir" "${CONFIG[system_name]}"
    
    # Optional features
    [[ "${CONFIG[init_git]}" == true ]] && init_git_repository "$scan_dir"
    [[ "${CONFIG[create_docker]}" == true ]] && create_dockerfile "$scan_dir"
    [[ "${CONFIG[encrypt_notes]}" == true ]] && setup_encryption "$scan_dir"
    [[ -n "${CONFIG[cloud_setup]}" ]] && setup_cloud "$scan_dir"
    [[ "${CONFIG[generate_report]}" == true ]] && generate_report "$scan_dir" "${CONFIG[system_name]}"
    [[ "${CONFIG[export_pdf]}" == true ]] && export_to_pdf "$scan_dir"
    [[ "${CONFIG[test_mode]}" == true ]] && run_tests "$scan_dir"
    
    # Install custom tools
    if [[ ${#CUSTOM_TOOLS[@]} -gt 0 ]]; then
        log "Installing custom tools..." "INFO"
        for tool in "${CUSTOM_TOOLS[@]}"; do
            if [[ "$tool" =~ ^git:(.+) ]]; then
                local repo_url="${BASH_REMATCH[1]}"
                local repo_name=$(basename "$repo_url" .git)
                git clone "$repo_url" "$scan_dir/tools/custom/$repo_name" 2>/dev/null || warn "Failed to clone $repo_name"
            elif [[ "$tool" =~ ^pip:(.+) ]]; then
                local pkg="${BASH_REMATCH[1]}"
                if [[ -f "$scan_dir/activate.sh" ]]; then
                    ( source "$scan_dir/activate.sh" && pip install "$pkg" ) || warn "Failed to install $pkg"
                fi
            fi
        done
    fi
    
    # Show summary
    show_summary "$scan_dir"
    success "Environment setup completed"
}

# Run main
main "$@"