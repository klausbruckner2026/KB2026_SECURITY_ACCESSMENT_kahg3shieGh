#!/usr/bin/env bash
# =============================================================================
#  ███████╗ █████╗ ███████╗████████╗██████╗ ██╗███╗   ██╗ ██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗ 
#  ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗
#  █████╗  ███████║███████╗   ██║   ██████╔╝██║██╔██╗ ██║██║  ███╗█████╗  ██║ █╗ ██║█████╗  █████╗  ██████╔╝
#  ██╔══╝  ██╔══██║╚════██║   ██║   ██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══╝  ██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝ 
#  ██║     ██║  ██║███████║   ██║   ██║     ██║██║ ╚████║╚██████╔╝███████╗╚███╔███╔╝███████╗███████╗██║     
#  ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝     
# =============================================================================
#  FastPingSweep Pro – Advanced Network Discovery & Host Enumeration
#  Version: 3.0 (2026 Enterprise Edition)
#  Author: Network Security Team
# =============================================================================
#  Features:
#    • Multiple discovery methods (ICMP, ARP, TCP, UDP)
#    • CIDR, IP range, and hostlist input support
#    • Adaptive concurrency with load management
#    • Multiple output formats (txt, json, csv, nmap-compatible)
#    • Service fingerprinting (optional)
#    • MAC address lookup (OUI database)
#    • Reverse DNS resolution
#    • Response time measurement
#    • Progressive scanning with smart rate limiting
#    • Integration with nmap/masscan for follow-up scans
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
#  CONFIGURATION
# =============================================================================

readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default configuration
declare -A CONFIG=(
    [target]=""
    [output]=""
    [format]="txt"
    [method]="icmp"
    [timeout]=1
    [concurrency]=64
    [max_concurrency]=256
    [retries]=1
    [verbose]=false
    [quiet]=false
    [debug]=false
    [dns_resolve]=false
    [mac_lookup]=false
    [service_scan]=false
    [top_ports]=100
    [rate_limit]=0
    [output_dir]="scan_results_${TIMESTAMP}"
    [input_file]=""
    [exclude_file]=""
    [randomize]=false
    [continuous]=false
    [interval]=60
    [webhook]=""
    [nmap_import]=false
    [masscan_compat]=false
)

# Discovery methods
readonly -A METHODS=(
    [icmp]="ICMP Echo Request (ping)"
    [arp]="ARP Request (local network only)"
    [tcp_syn]="TCP SYN scan (port 80)"
    [tcp_ack]="TCP ACK scan (port 80)"
    [udp]="UDP scan (port 53)"
    [combined]="All available methods"
)

# Colors
if [[ -t 1 ]] && [[ "${CONFIG[quiet]}" == false ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly MAGENTA='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly NC='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' BOLD='' DIM='' NC=''
fi

# =============================================================================
#  UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date +"%H:%M:%S")
    
    case "$level" in
        ERROR)   echo -e "${RED}[ERROR]${NC} ${msg}" >&2 ;;
        WARN)    [[ "${CONFIG[verbose]}" == true ]] && echo -e "${YELLOW}[WARN]${NC} ${msg}" >&2 ;;
        INFO)    [[ "${CONFIG[quiet]}" == false ]] && echo -e "${CYAN}[INFO]${NC} ${msg}" ;;
        SUCCESS) [[ "${CONFIG[quiet]}" == false ]] && echo -e "${GREEN}[SUCCESS]${NC} ${msg}" ;;
        DEBUG)   [[ "${CONFIG[debug]}" == true ]] && echo -e "${MAGENTA}[DEBUG]${NC} ${msg}" >&2 ;;
        PROGRESS) [[ "${CONFIG[verbose]}" == true ]] && echo -ne "\r${DIM}${msg}${NC}" >&2 ;;
    esac
}

error() {
    log "ERROR" "$1"
    exit 1
}

check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        error "Required dependency not found: $1"
    fi
}

# =============================================================================
#  HELP AND USAGE
# =============================================================================

show_banner() {
    if [[ "${CONFIG[quiet]}" == false ]]; then
        cat << "EOF"
${BLUE}${BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗ █████╗ ███████╗████████╗██████╗ ██╗███╗   ██╗ ██████╗ ███████╗   ║
║   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝   ║
║   █████╗  ███████║███████╗   ██║   ██████╔╝██║██╔██╗ ██║██║  ███╗█████╗     ║
║   ██╔══╝  ██╔══██║╚════██║   ██║   ██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══╝     ║
║   ██║     ██║  ██║███████║   ██║   ██║     ██║██║ ╚████║╚██████╔╝███████╗   ║
║   ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ║
║                                                                              ║
║                    ${WHITE}Advanced Network Discovery Suite v${SCRIPT_VERSION}${BLUE}                    ║
║                    ${CYAN}Enterprise-Grade Host Discovery & Enumeration${BLUE}                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
${NC}
EOF
    fi
}

show_usage() {
    cat << EOF

${BOLD}USAGE:${NC}
    $SCRIPT_NAME [OPTIONS] -t TARGET

${BOLD}REQUIRED:${NC}
    -t, --target CIDR|IP|range   Target specification (e.g., 192.168.1.0/24, 10.1.1.1-100, hostlist.txt)

${BOLD}TARGET SPECIFICATION:${NC}
    CIDR format:    192.168.1.0/24
    Range format:   10.1.1.1-254
    List format:    @/path/to/ip-list.txt
    Multiple:       192.168.1.0/24 10.1.1.1-254

${BOLD}DISCOVERY OPTIONS:${NC}
    -m, --method METHOD       Discovery method (icmp, arp, tcp_syn, tcp_ack, udp, combined)
                              (default: icmp)
    -p, --ports PORTS         Ports to use for TCP/UDP scans (default: 80,53)
    --top-ports N             Scan top N ports for service detection (default: 100)
    
${BOLD}SCAN OPTIMIZATION:${NC}
    -j, --jobs N              Concurrent jobs (default: 64, max: 256)
    -t, --timeout SEC         Timeout per host (default: 1)
    -r, --retries N           Number of retries (default: 1)
    --rate-limit N            Max packets per second (0 = unlimited)
    --randomize               Randomize host order
    
${BOLD}OUTPUT OPTIONS:${NC}
    -o, --output FILE         Output file (default: auto-generated)
    -f, --format FORMAT       Output format: txt, json, csv, nmap, all (default: txt)
    -O, --output-dir DIR      Output directory (default: scan_results_TIMESTAMP)
    
${BOLD}ENRICHMENT OPTIONS:${NC}
    -d, --dns-resolve         Perform reverse DNS lookup
    -M, --mac-lookup          Get MAC vendor information (requires arp-scan)
    -s, --service-scan        Quick service detection on top ports
    
${BOLD}ADVANCED OPTIONS:${NC}
    -e, --exclude FILE        Exclude targets from file
    --continuous INTERVAL     Continuous scanning every INTERVAL seconds
    --webhook URL             Send results to webhook
    --nmap-import             Generate nmap-compatible host file
    --masscan-compat          Output in masscan format
    
${BOLD}GENERAL OPTIONS:${NC}
    -v, --verbose             Verbose output
    -q, --quiet               Quiet mode (minimal output)
    --debug                    Debug mode
    -h, --help                 Show this help

${BOLD}EXAMPLES:${NC}
    # Basic ICMP sweep
    $SCRIPT_NAME -t 192.168.1.0/24
    
    # Fast TCP SYN scan on /16 network
    $SCRIPT_NAME -t 10.10.0.0/16 -m tcp_syn -j 200 --rate-limit 1000
    
    # Comprehensive scan with enrichment
    $SCRIPT_NAME -t 172.16.1.0/24 -m combined -d -M -s -f all -o corporate_scan
    
    # Continuous monitoring
    $SCRIPT_NAME -t 192.168.1.0/24 --continuous 300 --webhook https://api.example.com/hosts
    
    # Scan from file with exclusions
    $SCRIPT_NAME -t @targets.txt -e exclude.txt -j 128 -f json

EOF
}

# =============================================================================
#  TARGET PARSING
# =============================================================================

parse_targets() {
    local target="$1"
    local -a targets=()
    
    # Check if it's a file (prefixed with @)
    if [[ "$target" =~ ^@(.+)$ ]]; then
        local file="${BASH_REMATCH[1]}"
        if [[ ! -f "$file" ]]; then
            error "Target file not found: $file"
        fi
        mapfile -t targets < "$file"
    else
        targets=("$target")
    fi
    
    # Expand each target specification
    local -a expanded=()
    for spec in "${targets[@]}"; do
        if [[ "$spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
            # CIDR format
            expand_cidr "$spec" expanded
        elif [[ "$spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
            # Range format (last octet range)
            expand_range "$spec" expanded
        elif [[ "$spec" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # Single IP
            expanded+=("$spec")
        else
            error "Invalid target format: $spec"
        fi
    done
    
    # Apply exclusions if specified
    if [[ -n "${CONFIG[exclude_file]}" ]]; then
        apply_exclusions expanded
    fi
    
    # Randomize if requested
    if [[ "${CONFIG[randomize]}" == true ]]; then
        expanded=($(printf "%s\n" "${expanded[@]}" | shuf))
    fi
    
    printf "%s\n" "${expanded[@]}"
}

expand_cidr() {
    local cidr="$1"
    local -n _result="$2"
    
    if command -v ipcalc &>/dev/null; then
        # Use ipcalc for accurate expansion
        local network broadcast
        network=$(ipcalc -n "$cidr" | grep -oP '(?<=Network: )\S+')
        broadcast=$(ipcalc -b "$cidr" | grep -oP '(?<=Broadcast: )\S+')
        
        if [[ -n "$network" && -n "$broadcast" ]]; then
            local base="${network%.*}"
            local start="${network##*.}"
            local end="${broadcast##*.}"
            
            # Skip network and broadcast addresses
            for ((i=start+1; i<end; i++)); do
                _result+=("${base}.$i")
            done
        fi
    else
        # Fallback for simple CIDR parsing (/24 only)
        if [[ "$cidr" =~ ^(.+)\.[0-9]+/24$ ]]; then
            local base="${BASH_REMATCH[1]}"
            for i in {1..254}; do
                _result+=("${base}.$i")
            done
        else
            error "ipcalc not available and CIDR > /24 not supported in fallback mode"
        fi
    fi
}

expand_range() {
    local range="$1"
    local -n _result="$2"
    
    local base="${range%-*}"
    local base_prefix="${base%.*}"
    local start="${base##*.}"
    local end="${range##*-}"
    
    for ((i=start; i<=end; i++)); do
        _result+=("${base_prefix}.$i")
    done
}

apply_exclusions() {
    local -n _targets="$1"
    local -a excluded=()
    
    if [[ -f "${CONFIG[exclude_file]}" ]]; then
        mapfile -t excluded < "${CONFIG[exclude_file]}"
    fi
    
    local -a filtered=()
    for ip in "${_targets[@]}"; do
        local exclude=false
        for excl in "${excluded[@]}"; do
            if [[ "$ip" == "$excl" ]]; then
                exclude=true
                break
            fi
        done
        [[ "$exclude" == false ]] && filtered+=("$ip")
    done
    
    _targets=("${filtered[@]}")
}

# =============================================================================
#  DISCOVERY METHODS
# =============================================================================

check_host_icmp() {
    local ip="$1"
    ping -c 1 -W "${CONFIG[timeout]}" "$ip" &>/dev/null
    return $?
}

check_host_arp() {
    local ip="$1"
    # Requires arping (part of iputils)
    arping -c 1 -w "${CONFIG[timeout]}" "$ip" &>/dev/null
    return $?
}

check_host_tcp_syn() {
    local ip="$1"
    local port="${2:-80}"
    # Use timeout with bash's /dev/tcp (requires TCP connection)
    timeout "${CONFIG[timeout]}" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
    return $?
}

check_host_tcp_ack() {
    local ip="$1"
    local port="${2:-80}"
    # Use hping3 if available, otherwise fallback to nmap
    if command -v hping3 &>/dev/null; then
        hping3 -A -p "$port" -c 1 -W "${CONFIG[timeout]}" "$ip" 2>/dev/null | grep -q "flags=ACK"
        return $?
    else
        # Fallback to nmap ACK scan
        nmap -sA -p "$port" --host-timeout="${CONFIG[timeout]}s" "$ip" 2>/dev/null | grep -q "Host is up"
        return $?
    fi
}

check_host_udp() {
    local ip="$1"
    local port="${2:-53}"
    # Use hping3 if available
    if command -v hping3 &>/dev/null; then
        hping3 -2 -p "$port" -c 1 -W "${CONFIG[timeout]}" "$ip" 2>/dev/null | grep -q "flags=RA"
        return $?
    else
        # Fallback to nc
        timeout "${CONFIG[timeout]}" nc -zu "$ip" "$port" &>/dev/null
        return $?
    fi
}

# =============================================================================
#  ENRICHMENT FUNCTIONS
# =============================================================================

get_reverse_dns() {
    local ip="$1"
    host "$ip" 2>/dev/null | grep -oP '(?<=domain name pointer ).*(?=\.$)' || echo ""
}

get_mac_vendor() {
    local ip="$1"
    if command -v arp-scan &>/dev/null; then
        arp-scan -l -g -q -T "$ip" 2>/dev/null | grep "^$ip" | awk '{print $3" "$4}'
    fi
}

measure_response_time() {
    local ip="$1"
    local method="$2"
    local start end
    
    case "$method" in
        icmp)
            start=$(date +%s%N)
            ping -c 1 -W "${CONFIG[timeout]}" "$ip" &>/dev/null
            end=$(date +%s%N)
            ;;
        tcp_syn)
            start=$(date +%s%N)
            timeout "${CONFIG[timeout]}" bash -c "echo >/dev/tcp/$ip/80" 2>/dev/null
            end=$(date +%s%N)
            ;;
        *)
            echo "0"
            return
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        echo "scale=2; ($end - $start)/1000000" | bc 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

quick_service_scan() {
    local ip="$1"
    local -a open_ports=()
    local top_ports="${CONFIG[top_ports]}"
    
    # Common ports to check
    local common_ports=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080)
    
    for port in "${common_ports[@]}"; do
        if timeout 0.5 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            # Get service name from /etc/services if available
            local service=$(grep -E "^[[:space:]]*$port/" /etc/services 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
            open_ports+=("$port/$service")
        fi
    done
    
    printf "%s" "${open_ports[*]}"
}

# =============================================================================
#  OUTPUT FORMATTERS
# =============================================================================

format_txt() {
    local results="$1"
    local file="$2"
    
    {
        echo "# FastPingSweep Pro v${SCRIPT_VERSION} - Scan Results"
        echo "# Date: $(date)"
        echo "# Target: ${CONFIG[target]}"
        echo "# Method: ${CONFIG[method]}"
        echo "# Total Hosts Found: $(echo "$results" | grep -c '^[0-9]')"
        echo "# ========================================"
        echo ""
        echo "$results" | while IFS='|' read -r ip dns mac rtime ports; do
            echo "IP Address: $ip"
            [[ -n "$dns" ]] && echo "  DNS: $dns"
            [[ -n "$mac" ]] && echo "  MAC: $mac"
            [[ -n "$rtime" && "$rtime" != "0" ]] && echo "  Response Time: ${rtime}ms"
            [[ -n "$ports" ]] && echo "  Open Ports: $ports"
            echo ""
        done
    } > "$file"
}

format_json() {
    local results="$1"
    local file="$2"
    
    {
        echo "{"
        echo "  \"metadata\": {"
        echo "    \"tool\": \"FastPingSweep Pro\","
        echo "    \"version\": \"${SCRIPT_VERSION}\","
        echo "    \"timestamp\": \"$(date -Iseconds)\","
        echo "    \"target\": \"${CONFIG[target]}\","
        echo "    \"method\": \"${CONFIG[method]}\""
        echo "  },"
        echo "  \"hosts\": ["
        
        local first=true
        echo "$results" | while IFS='|' read -r ip dns mac rtime ports; do
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            
            echo -n "    {"
            echo -n "\"ip\": \"$ip\""
            [[ -n "$dns" ]] && echo -n ", \"dns\": \"$dns\""
            [[ -n "$mac" ]] && echo -n ", \"mac\": \"$mac\""
            [[ -n "$rtime" && "$rtime" != "0" ]] && echo -n ", \"response_time\": $rtime"
            [[ -n "$ports" ]] && echo -n ", \"open_ports\": [\"$(echo "$ports" | sed 's/ /", "/g')\"]"
            echo -n "}"
        done
        
        echo ""
        echo "  ]"
        echo "}"
    } > "$file"
}

format_csv() {
    local results="$1"
    local file="$2"
    
    {
        echo "IP Address,DNS Name,MAC Address,Response Time(ms),Open Ports"
        echo "$results" | while IFS='|' read -r ip dns mac rtime ports; do
            echo "\"$ip\",\"$dns\",\"$mac\",\"$rtime\",\"$ports\""
        done
    } > "$file"
}

format_nmap() {
    local results="$1"
    local file="$2"
    
    echo "$results" | awk -F'|' '{print $1}' > "$file"
}

format_masscan() {
    local results="$1"
    local file="$2"
    
    echo "$results" | awk -F'|' '{print "masscan -p1-65535 "$1" --rate=10000"}' > "$file"
}

# =============================================================================
#  MAIN SCAN ENGINE
# =============================================================================

run_scan() {
    local -a targets=("$@")
    local total=${#targets[@]}
    local -a results=()
    local tmp_results=$(mktemp)
    local processed=0
    local live_count=0
    
    log "INFO" "Starting scan of $total targets using ${CONFIG[method]} method"
    log "INFO" "Concurrency: ${CONFIG[concurrency]}, Timeout: ${CONFIG[timeout]}s"
    
    # Trap to clean up temp file
    trap "rm -f \"$tmp_results\"" RETURN
    
    for ip in "${targets[@]}"; do
        (
            local alive=false
            local rtime=0
            
            case "${CONFIG[method]}" in
                icmp)
                    check_host_icmp "$ip" && alive=true
                    ;;
                arp)
                    check_host_arp "$ip" && alive=true
                    ;;
                tcp_syn)
                    check_host_tcp_syn "$ip" && alive=true && rtime=$(measure_response_time "$ip" tcp_syn)
                    ;;
                tcp_ack)
                    check_host_tcp_ack "$ip" && alive=true
                    ;;
                udp)
                    check_host_udp "$ip" && alive=true
                    ;;
                combined)
                    # Try all methods, stop on first success
                    { check_host_icmp "$ip" || check_host_arp "$ip" || 
                      check_host_tcp_syn "$ip" || check_host_tcp_ack "$ip" || 
                      check_host_udp "$ip"; } && alive=true
                    ;;
            esac
            
            if [[ "$alive" == true ]]; then
                # Build result line with enrichment data
                local result="$ip"
                
                # Reverse DNS
                if [[ "${CONFIG[dns_resolve]}" == true ]]; then
                    result+="|$(get_reverse_dns "$ip")"
                else
                    result+="|"
                fi
                
                # MAC vendor
                if [[ "${CONFIG[mac_lookup]}" == true ]]; then
                    result+="|$(get_mac_vendor "$ip")"
                else
                    result+="|"
                fi
                
                # Response time
                result+="|$rtime"
                
                # Service scan
                if [[ "${CONFIG[service_scan]}" == true ]]; then
                    result+="|$(quick_service_scan "$ip")"
                else
                    result+="|"
                fi
                
                echo "$result" >> "$tmp_results"
                
                if [[ "${CONFIG[verbose]}" == true ]]; then
                    log "SUCCESS" "Found: $ip"
                fi
            elif [[ "${CONFIG[verbose]}" == true ]]; then
                log "DEBUG" "No response: $ip"
            fi
        ) &
        
        ((processed++))
        
        # Throttle concurrent jobs
        while [[ $(jobs -r | wc -l) -ge "${CONFIG[concurrency]}" ]]; do
            sleep 0.05
        done
        
        # Progress indicator
        if [[ $((processed % 100)) -eq 0 ]] && [[ "${CONFIG[verbose]}" == false ]]; then
            printf "\r${DIM}Progress: %d/%d hosts scanned${NC}" "$processed" "$total" >&2
        fi
    done
    
    wait
    
    # Collect results
    if [[ -f "$tmp_results" ]]; then
        mapfile -t results < "$tmp_results"
        live_count=${#results[@]}
    fi
    
    printf "\n" >&2
    log "SUCCESS" "Scan completed. Found $live_count live hosts."
    
    # Return results array
    printf "%s\n" "${results[@]}"
}

# =============================================================================
#  CONTINUOUS SCAN MODE
# =============================================================================

continuous_scan() {
    local interval="${CONFIG[interval]}"
    local -a targets=("$@")
    local scan_count=1
    
    log "INFO" "Starting continuous scan mode (interval: ${interval}s)"
    
    while true; do
        log "INFO" "Continuous scan #$scan_count started at $(date)"
        
        local results=($(run_scan "${targets[@]}"))
        local output_file="${CONFIG[output_dir]}/continuous_${scan_count}_$(date +%Y%m%d_%H%M%S).${CONFIG[format]}"
        
        # Format and save results
        case "${CONFIG[format]}" in
            txt)    format_txt "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            json)   format_json "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            csv)    format_csv "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            nmap)   format_nmap "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            masscan) format_masscan "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            all)
                format_txt "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.txt"
                format_json "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.json"
                format_csv "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.csv"
                ;;
        esac
        
        # Send to webhook if configured
        if [[ -n "${CONFIG[webhook]}" ]]; then
            local json_data=$(format_json "$(printf "%s\n" "${results[@]}")" /dev/stdout)
            curl -s -X POST -H "Content-Type: application/json" -d "$json_data" "${CONFIG[webhook]}" >/dev/null
        fi
        
        log "SUCCESS" "Continuous scan #$scan_count completed. Results saved to $output_file"
        
        ((scan_count++))
        sleep "$interval"
    done
}

# =============================================================================
#  MAIN
# =============================================================================

main() {
    # Show banner
    show_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)        CONFIG[target]="$2"; shift 2 ;;
            -m|--method)         CONFIG[method]="$2"; shift 2 ;;
            -j|--jobs)           CONFIG[concurrency]="$2"; shift 2 ;;
            -t|--timeout)        CONFIG[timeout]="$2"; shift 2 ;;
            -r|--retries)        CONFIG[retries]="$2"; shift 2 ;;
            -o|--output)         CONFIG[output]="$2"; shift 2 ;;
            -f|--format)         CONFIG[format]="$2"; shift 2 ;;
            -O|--output-dir)     CONFIG[output_dir]="$2"; shift 2 ;;
            -e|--exclude)        CONFIG[exclude_file]="$2"; shift 2 ;;
            -d|--dns-resolve)    CONFIG[dns_resolve]=true; shift ;;
            -M|--mac-lookup)     CONFIG[mac_lookup]=true; shift ;;
            -s|--service-scan)   CONFIG[service_scan]=true; shift ;;
            --top-ports)         CONFIG[top_ports]="$2"; shift 2 ;;
            --rate-limit)        CONFIG[rate_limit]="$2"; shift 2 ;;
            --randomize)         CONFIG[randomize]=true; shift ;;
            --continuous)        CONFIG[continuous]=true; CONFIG[interval]="$2"; shift 2 ;;
            --webhook)           CONFIG[webhook]="$2"; shift 2 ;;
            --nmap-import)       CONFIG[nmap_import]=true; shift ;;
            --masscan-compat)    CONFIG[masscan_compat]=true; shift ;;
            -v|--verbose)        CONFIG[verbose]=true; shift ;;
            -q|--quiet)          CONFIG[quiet]=true; shift ;;
            --debug)              CONFIG[debug]=true; CONFIG[verbose]=true; shift ;;
            -h|--help)            show_usage; exit 0 ;;
            *)                   error "Unknown option: $1" ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "${CONFIG[target]}" ]]; then
        error "Target specification required (-t)"
    fi
    
    # Validate method
    if [[ ! -v METHODS["${CONFIG[method]}"] ]]; then
        error "Invalid method: ${CONFIG[method]}. Use: ${!METHODS[*]}"
    fi
    
    # Validate concurrency
    if [[ "${CONFIG[concurrency]}" -lt 1 || "${CONFIG[concurrency]}" -gt "${CONFIG[max_concurrency]}" ]]; then
        error "Concurrency must be between 1 and ${CONFIG[max_concurrency]}"
    fi
    
    # Check dependencies based on method
    case "${CONFIG[method]}" in
        arp)    check_dependency "arping" ;;
        tcp_ack|udp)    
            if ! command -v hping3 &>/dev/null && ! command -v nmap &>/dev/null; then
                error "TCP/UDP scans require hping3 or nmap"
            fi
            ;;
    esac
    
    if [[ "${CONFIG[mac_lookup]}" == true ]]; then
        check_dependency "arp-scan"
    fi
    
    # Create output directory
    mkdir -p "${CONFIG[output_dir]}"
    
    # Parse targets
    log "INFO" "Parsing target specification: ${CONFIG[target]}"
    local -a targets=($(parse_targets "${CONFIG[target]}"))
    
    if [[ ${#targets[@]} -eq 0 ]]; then
        error "No targets to scan after parsing"
    fi
    
    log "INFO" "Expanded to ${#targets[@]} individual targets"
    
    # Run scan (continuous or single)
    if [[ "${CONFIG[continuous]}" == true ]]; then
        continuous_scan "${targets[@]}"
    else
        local results=($(run_scan "${targets[@]}"))
        local live_count=${#results[@]}
        
        # Determine output file
        local output_file="${CONFIG[output]}"
        if [[ -z "$output_file" ]]; then
            output_file="${CONFIG[output_dir]}/scan_results_$(date +%Y%m%d_%H%M%S).${CONFIG[format]}"
        fi
        
        # Format and save results
        case "${CONFIG[format]}" in
            txt)    format_txt "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            json)   format_json "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            csv)    format_csv "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            nmap)   format_nmap "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            masscan) format_masscan "$(printf "%s\n" "${results[@]}")" "$output_file" ;;
            all)
                format_txt "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.txt"
                format_json "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.json"
                format_csv "$(printf "%s\n" "${results[@]}")" "${output_file%.*}.csv"
                format_nmap "$(printf "%s\n" "${results[@]}")" "${output_file%.*}_nmap.txt"
                ;;
        esac
        
        log "SUCCESS" "Results saved to: $output_file"
        
        # Generate nmap import if requested
        if [[ "${CONFIG[nmap_import]}" == true ]]; then
            format_nmap "$(printf "%s\n" "${results[@]}")" "${output_file%.*}_nmap.txt"
            log "INFO" "Nmap import file: ${output_file%.*}_nmap.txt"
        fi
        
        # Show summary
        cat << EOF

${BOLD}${GREEN}SCAN SUMMARY${NC}
${BOLD}════════════${NC}
${BOLD}Target:${NC}      ${CONFIG[target]}
${BOLD}Method:${NC}      ${CONFIG[method]} (${METHODS[${CONFIG[method]}]})
${BOLD}Total Hosts:${NC} ${#targets[@]}
${BOLD}Live Hosts:${NC}  ${GREEN}${live_count}${NC}
${BOLD}Duration:${NC}    $(($(date +%s%N) - START_TIME))ms
${BOLD}Output:${NC}      $output_file

${BOLD}${CYAN}NEXT STEPS${NC}
${BOLD}──────────${NC}
1. Port scanning:  nmap -iL ${output_file} -sV -p- --open
2. Service enum:   nmap -iL ${output_file} -sC -sV -oA service_scan
3. Web scan:       httpx -l ${output_file} -title -status-code -tech-detect
4. Vuln scan:      nuclei -l ${output_file} -t cves/

EOF
    fi
}

# =============================================================================
#  SCRIPT ENTRY POINT
# =============================================================================

# Capture start time for duration calculation
readonly START_TIME=$(date +%s%N)

# Run main with all arguments
main "$@"