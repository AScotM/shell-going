#!/bin/bash

# TCP/UDP Connection Monitor - Enhanced Shell Script Version (Overkill Edition)
# Parses /proc/net/{tcp,udp,tcp6,udp6} to show active IPv4/IPv6 TCP/UDP connections
# Updates: Robust awk parsing, fixed IPv6 conversion, proper IPv4 CIDR matching,
#          added UDP support, CSV/JSON outputs, alert mode, config file, version.
# Fix: Skip empty states in stats to avoid bad subscript.

set -eo pipefail  # Remove -u to avoid unbound variable issues, we'll handle them manually

# Color codes for output
readonly RED='\033[31m'
readonly GREEN='\033[32m'
readonly YELLOW='\033[33m'
readonly BLUE='\033[34m'
readonly MAGENTA='\033[35m'
readonly CYAN='\033[36m'
readonly WHITE='\033[37m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# TCP/UDP state mappings (from Linux kernel; UDP has no states, but we use "ESTABLISHED" for active)
declare -rA TCP_STATES=(
    ["01"]="ESTABLISHED"
    ["02"]="SYN_SENT"
    ["03"]="SYN_RECV"
    ["04"]="FIN_WAIT1"
    ["05"]="FIN_WAIT2"
    ["06"]="TIME_WAIT"
    ["07"]="CLOSE"
    ["08"]="CLOSE_WAIT"
    ["09"]="LAST_ACK"
    ["0A"]="LISTEN"
    ["0B"]="CLOSING"
    ["0C"]="NEW_SYN_RECV"
)
# UDP states (simplified)
declare -rA UDP_STATES=(
    ["0A"]="LISTEN"  # UDP listen
    ["07"]="UNCONNECTED"  # Default for UDP
)

# Combined state colors
declare -rA STATE_COLORS=(
    ["LISTEN"]="$GREEN"
    ["ESTABLISHED"]="$CYAN"
    ["TIME_WAIT"]="$YELLOW"
    ["CLOSE_WAIT"]="$RED"
    ["FIN_WAIT1"]="$MAGENTA"
    ["FIN_WAIT2"]="$MAGENTA"
    ["SYN_SENT"]="$BLUE"
    ["SYN_RECV"]="$BLUE"
    ["UNCONNECTED"]="$WHITE"
    ["UNKNOWN"]="$RED"
)

# Configuration defaults (load from config file later)
declare -g REFRESH_INTERVAL=2
declare -g PROCESS_CACHE_TTL=5
declare -g MAX_DISPLAY_PROCESSES=10
declare -g CONNECTION_CACHE_TTL=1
declare -g SHOW_UDP=false
declare -g CSV_OUTPUT=false
declare -g ALERT_STATE=""
declare -g ALERT_THRESHOLD=0

# Global variables with safe initialization
declare -gA PROCESS_CACHE=()
declare -gA CONNECTION_CACHE=()
declare -g LAST_PROCESS_SCAN=0
declare -g LAST_CONNECTION_SCAN=0
declare -g JSON_OUTPUT=false
declare -g SHOW_PROCESSES=false
declare -g SHOW_COUNT=false
declare -g SHOW_STATS=false
declare -g WATCH_MODE=false
declare -g VERBOSE=false
declare -g ALERT_MODE=false
declare -ga FILTER_STATES=()
declare -g FILTER_PORT=""
declare -g FILTER_LOCAL_IP=""
declare -g FILTER_REMOTE_IP=""
declare -g FILTER_IPV4=false
declare -g FILTER_IPV6=false
declare -g OUTPUT_FILE=""
declare -g SCRIPT_START_TIME
declare -g OPERATION_COUNT=0
declare -g SCRIPT_VERSION="2.0-overkill"

SCRIPT_START_TIME=$(date +%s.%N)

# Load config file
load_config() {
    local config_file="${HOME}/.tcpmonrc"
    if [[ -r "$config_file" ]]; then
        # Source it safely (only known vars)
        while IFS='=' read -r key value; do
            case "$key" in
                REFRESH_INTERVAL|PROCESS_CACHE_TTL|MAX_DISPLAY_PROCESSES|CONNECTION_CACHE_TTL|ALERT_THRESHOLD)
                    if [[ "$value" =~ ^[0-9]+$ ]]; then
                        declare -g "$key"="$value"
                    fi
                    ;;
                SHOW_UDP) declare -g "$key"=$( [[ "$value" == "true" ]] && echo "true" || echo "false" ) ;;
                ALERT_STATE) declare -g "$key"="$value" ;;
            esac
        done < "$config_file"
        info "Loaded config from $config_file"
    fi
}

# Safe variable access function
safe_get() {
    local var_name="$1"
    local default="${2:-}"
    if [[ -v "$var_name" ]]; then
        echo "${!var_name}"
    else
        echo "$default"
    fi
}

# Error handling
die() {
    echo -e "${RED}Error:${RESET} $1" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}Warning:${RESET} $1" >&2
}

info() {
    if [[ "$(safe_get 'VERBOSE')" == "true" ]]; then
        echo -e "${BLUE}Info:${RESET} $1" >&2
    fi
}

# Performance tracking
record_operation() {
    OPERATION_COUNT=$((OPERATION_COUNT + 1))
}

get_performance_metrics() {
    local end_time=$(date +%s.%N)
    local execution_time=$(echo "$end_time - $SCRIPT_START_TIME" | bc -l 2>/dev/null || awk "BEGIN {print $end_time - $SCRIPT_START_TIME}")
    local memory_peak=0
    local memory_peak_mb=0
    
    if [[ -f "/proc/$$/status" ]]; then
        memory_peak=$(grep VmPeak "/proc/$$/status" 2>/dev/null | awk '{print $2}' || echo "0")
        memory_peak_mb=$(echo "scale=2; $memory_peak / 1024" | bc -l 2>/dev/null || awk "BEGIN {print $memory_peak / 1024}")
    fi
    
    cat << EOF
Execution time: $(printf "%.3f" "$execution_time")s
Memory peak: ${memory_peak_mb} MB
Operations: $OPERATION_COUNT
EOF
}

# Validation functions
validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        die "Port must be between 1 and 65535"
    fi
}

validate_interval() {
    local interval="$1"
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 ]] || [[ "$interval" -gt 3600 ]]; then
        die "Interval must be between 1 and 3600 seconds"
    fi
}

validate_threshold() {
    local threshold="$1"
    if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [[ "$threshold" -lt 0 ]]; then
        die "Threshold must be a non-negative integer"
    fi
}

validate_ip_cidr() {
    local ip_cidr="$1"
    if [[ "$ip_cidr" == *"/"* ]]; then
        local ip="${ip_cidr%/*}"
        local mask="${ip_cidr#*/}"
        if ! [[ "$mask" =~ ^[0-9]+$ ]] || [[ "$mask" -lt 0 ]] || [[ "$mask" -gt 32 && "${ip:0:1}" == "0" && "${ip:0:3}" != "::" ]] || [[ "$mask" -gt 128 ]]; then
            die "Invalid CIDR mask: $mask (IPv4: 0-32, IPv6: 0-128)"
        fi
    fi
    # Basic IP validation
    if [[ ! "$ip_cidr" =~ ^[0-9a-fA-F.:/]+$ ]]; then
        die "Invalid IP or CIDR format: $ip_cidr"
    fi
}

# IPv4 int conversion for CIDR matching
ip4_to_int() {
    local ip="$1"
    IFS='.' read -ra octets <<< "$ip"
    echo "$(( (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3] ))"
}

cidr4_match() {
    local ip="$1" network="$2" mask="$3"
    local ip_int=$(ip4_to_int "$ip")
    local net_int=$(ip4_to_int "$network")
    local mask_int=$(( 0xFFFFFFFF << (32 - mask) ))
    [[ $(( ip_int & mask_int )) -eq $(( net_int & mask_int )) ]]
}

# IPv6 CIDR: Simplified prefix match (full bitmask too complex in bash; use awk if needed)
cidr6_match() {
    local ip="$1" network="$2" mask="$3"
    # Basic prefix: check if ip starts with network up to mask bits
    local prefix_len=$(( mask / 4 ))
    local ip_prefix="${ip:0:$prefix_len}"
    local net_prefix="${network:0:$prefix_len}"
    [[ "$ip_prefix" == "$net_prefix" ]]
}

ip_matches_filter() {
    local ip="$1" filter="$2" family="$3"
    
    # Exact match
    if [[ "$ip" == "$filter" ]]; then
        return 0
    fi
    
    if [[ "$filter" == *"/"* ]]; then
        local network="${filter%/*}"
        local mask="${filter#*/}"
        
        if [[ "$family" == "ipv4" ]]; then
            cidr4_match "$ip" "$network" "$mask"
        else
            cidr6_match "$ip" "$network" "$mask"
        fi
    else
        # Subnet fallback (warned as approximate)
        if [[ "$ip" == *"$filter"* ]]; then
            return 0
        fi
    fi
    
    return 1
}

# System checks
check_requirements() {
    if [[ "$(uname)" != "Linux" ]]; then
        die "This script only works on Linux systems"
    fi
    
    if [[ ! -d "/proc" ]]; then
        die "/proc filesystem not available"
    fi
    
    if [[ "$(safe_get 'SHOW_PROCESSES')" == "true" ]] && [[ "$EUID" -ne 0 ]]; then
        warn "Some process information may be limited without root privileges"
    fi
    
    # Check for required commands
    local required_cmds=("grep" "awk" "sort" "bc")
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            die "Required command '$cmd' not found"
        fi
    done
}

# Display help message
show_help() {
    cat << EOF
${BOLD}TCP/UDP Connection Monitor v${SCRIPT_VERSION}${RESET}

${BOLD}Usage:${RESET} $0 [options]

${BOLD}Options:${RESET}
  ${BOLD}--json${RESET}              Output connections in JSON format
  ${BOLD}--csv${RESET}               Output connections in CSV format
  ${BOLD}--udp${RESET}               Include UDP connections
  ${BOLD}--listen${RESET}            Show only listening sockets
  ${BOLD}--established${RESET}       Show only established connections  
  ${BOLD}--timewait${RESET}          Show only TIME_WAIT connections
  ${BOLD}--closewait${RESET}         Show only CLOSE_WAIT connections
  ${BOLD}--finwait${RESET}           Show only FIN_WAIT1/FIN_WAIT2 connections
  ${BOLD}--count${RESET}             Only show counts (IPv4/IPv6/total/TCP/UDP)
  ${BOLD}--processes${RESET}         Show process information (slower)
  ${BOLD}--port NUM${RESET}          Filter by port number
  ${BOLD}--local-ip IP${RESET}       Filter by local IP address (supports CIDR)
  ${BOLD}--remote-ip IP${RESET}      Filter by remote IP address (supports CIDR)
  ${BOLD}--ipv4${RESET}              Show only IPv4 connections
  ${BOLD}--ipv6${RESET}              Show only IPv6 connections
  ${BOLD}--watch [SEC]${RESET}       Refresh continuously (default: 2s)
  ${BOLD}--stats${RESET}             Show detailed statistics
  ${BOLD}--alert-state STATE${RESET} Enable alerts for state (e.g., CLOSE_WAIT)
  ${BOLD}--alert-threshold N${RESET} Alert if count > N (default: 0)
  ${BOLD}--output FILE${RESET}       Write output to file
  ${BOLD}--verbose, -v${RESET}       Show performance metrics and debug info
  ${BOLD}--version${RESET}           Show version
  ${BOLD}--help${RESET}              Show this help message

${BOLD}Config:${RESET} Edit ~/.tcpmonrc for defaults (e.g., REFRESH_INTERVAL=5)

${BOLD}Examples:${RESET}
  $0 --listen --processes --udp
  $0 --established --json
  $0 --port 80 --ipv4
  $0 --watch 5 --stats
  $0 --local-ip "192.168.1.0/24" --alert-state CLOSE_WAIT --alert-threshold 50
  $0 --csv --output connections.csv

${BOLD}Note:${RESET} Requires Linux and access to /proc filesystem
EOF
}

show_version() {
    echo "TCP/UDP Connection Monitor v${SCRIPT_VERSION}"
    exit 0
}

# Convert hex to decimal (with padding)
hex_to_dec() {
    local hex="$1"
    hex=$(printf "%08x" "0x$hex" 2>/dev/null | tr '[:lower:]' '[:upper:]')  # Pad and normalize
    printf "%d" "0x$hex" 2>/dev/null || echo "0"
}

# Convert hex IPv4 to dotted decimal (robust)
hex_to_ipv4() {
    local hex="$1"
    hex=$(printf "%08x" "0x$hex" 2>/dev/null)  # Pad to 8 chars
    local o1=$(hex_to_dec "${hex:0:2}")
    local o2=$(hex_to_dec "${hex:2:2}")
    local o3=$(hex_to_dec "${hex:4:2}")
    local o4=$(hex_to_dec "${hex:6:2}")
    printf "%d.%d.%d.%d" "$o1" "$o2" "$o3" "$o4"
}

# Convert hex IPv6 to compressed format (fixed: no reversal, proper hextets)
hex_to_ipv6() {
    local hex="$1"
    hex=$(printf "%032x" "0x$hex" 2>/dev/null)  # Pad to 32 chars, lowercase
    if [[ "${#hex}" -ne 32 ]]; then
        echo "::"
        return 1
    fi
    
    # Split into 8 hextets of 4 chars each (big-endian, no reverse)
    local hextets=()
    local i
    for ((i=0; i<32; i+=4)); do
        local hextet="${hex:$i:4}"
        # Zero-compress single hextet
        if [[ "$hextet" == "0000" ]]; then
            hextet="0"
        else
            hextet=$(printf "%x" "0x$hextet")  # Ensure lowercase
        fi
        hextets+=("$hextet")
    done
    
    # Compress longest zeros
    local compressed=$(IFS=:; echo "${hextets[*]}")
    local longest_start=0 longest_length=0
    local current_start=0 current_length=0
    
    for ((i=0; i<8; i++)); do
        if [[ "${hextets[i]}" == "0" ]]; then
            if [[ $current_length -eq 0 ]]; then
                current_start=$i
            fi
            ((current_length++))
        else
            if [[ $current_length -gt $longest_length ]]; then
                longest_start=$current_start
                longest_length=$current_length
            fi
            current_length=0
        fi
    done
    
    if [[ $current_length -gt $longest_length ]]; then
        longest_start=$current_start
        longest_length=$current_length
    fi
    
    if [[ $longest_length -gt 1 ]]; then
        local before=() after=()
        for ((i=0; i<longest_start; i++)); do
            before+=("${hextets[i]}")
        done
        for ((i=$((longest_start + longest_length)); i<8; i++)); do
            after+=("${hextets[i]}")
        done
        
        if [[ ${#before[@]} -eq 0 && ${#after[@]} -eq 0 ]]; then
            compressed="::"
        elif [[ ${#before[@]} -eq 0 ]]; then
            compressed="::$(IFS=:; echo "${after[*]}")"
        elif [[ ${#after[@]} -eq 0 ]]; then
            compressed="$(IFS=:; echo "${before[*]}")::"
        else
            compressed="$(IFS=:; echo "${before[*]}")::$(IFS=:; echo "${after[*]}")"
        fi
    fi
    
    echo "$compressed"
}

# Process cache management (unchanged, but added UDP inodes)
build_process_map() {
    local current_time=$(date +%s)
    info "Building process map..."
    
    PROCESS_CACHE=()
    
    # Extract inodes from all proto files
    local inodes=()
    local proto_files=("/proc/net/tcp" "/proc/net/tcp6" "/proc/net/udp" "/proc/net/udp6")
    local file
    for file in "${proto_files[@]}"; do
        if [[ -f "$file" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ [[:space:]]+[0-9]+:[[:space:]]+[0-9A-F:]+[[:space:]]+[0-9A-F:]+[[:space:]]+[0-9A-F]+[[:space:]]+[0-9A-F]+[[:space:]]+[0-9A-F]+[[:space:]]+[0-9A-F]+[[:space:]]+[0-9A-F]+[[:space:]]+[0-9A-F]+[[:space:]]+([0-9]+) ]]; then
                    inodes+=("${BASH_REMATCH[1]}")
                fi
            done < <(tail -n +2 "$file" 2>/dev/null || true)
        fi
    done
    
    # Dedup inodes
    local -A inode_lookup=()
    for inode in "${inodes[@]}"; do
        inode_lookup["$inode"]=1
    done
    
    # Scan /proc
    local pid_dir
    for pid_dir in /proc/[0-9]*/; do
        [[ ! -d "$pid_dir" ]] && continue
        
        local pid=$(basename "$pid_dir")
        
        if [[ ! -r "${pid_dir}fd" ]] || [[ ! -d "${pid_dir}fd" ]]; then
            continue
        fi
        
        local process_name="unknown"
        if [[ -r "${pid_dir}comm" ]]; then
            process_name=$(cat "${pid_dir}comm" 2>/dev/null | xargs || echo "unknown")
            process_name="${process_name} (PID: $pid)"
        else
            process_name="PID: $pid"
        fi
        
        local fd
        for fd in "${pid_dir}fd"/[0-9]*; do
            [[ ! -r "$fd" ]] && continue
            
            local link
            link=$(readlink "$fd" 2>/dev/null) || continue
            
            if [[ "$link" =~ socket:\[([0-9]+)\] ]] && [[ -n "${inode_lookup[${BASH_REMATCH[1]}]:-}" ]]; then
                PROCESS_CACHE["${BASH_REMATCH[1]}"]="$process_name"
            fi
        done
    done
    
    LAST_PROCESS_SCAN=$current_time
    info "Process map built with ${#PROCESS_CACHE[@]} entries"
}

get_process_by_inode() {
    local inode="$1"
    local current_time=$(date +%s)
    
    if [[ $((current_time - LAST_PROCESS_SCAN)) -ge "$PROCESS_CACHE_TTL" ]] || [[ ${#PROCESS_CACHE[@]} -eq 0 ]]; then
        build_process_map
    fi
    
    echo "${PROCESS_CACHE[$inode]:-unknown}"
}

# Connection cache management (unchanged)
get_cached_connections() {
    local file="$1" family="$2" proto="$3"
    local current_time=$(date +%s)
    local cache_key="${file}_${family}_${proto}"
    local file_mtime=$(stat -c %Y "$file" 2>/dev/null || echo "0")
    local cache_mtime="${CONNECTION_CACHE[${cache_key}_mtime]:-0}"
    
    if [[ $((current_time - LAST_CONNECTION_SCAN)) -lt "$CONNECTION_CACHE_TTL" ]] && 
       [[ -n "${CONNECTION_CACHE[$cache_key]:-}" ]] &&
       [[ "$cache_mtime" -eq "$file_mtime" ]]; then
        echo "${CONNECTION_CACHE[$cache_key]}"
        return 0
    fi
    
    return 1
}

cache_connections() {
    local file="$1" family="$2" proto="$3" data="$4"
    local cache_key="${file}_${family}_${proto}"
    local file_mtime=$(stat -c %Y "$file" 2>/dev/null || echo "0")
    
    CONNECTION_CACHE["$cache_key"]="$data"
    CONNECTION_CACHE["${cache_key}_mtime"]="$file_mtime"
    LAST_CONNECTION_SCAN=$(date +%s)
}

# Parse proto file with awk (robust!)
parse_proto_file() {
    local file="$1" family="$2" proto="$3"
    
    if [[ ! -r "$file" ]]; then
        warn "Cannot read file: $file"
        return 1
    fi
    
    local cached_data
    if cached_data=$(get_cached_connections "$file" "$family" "$proto"); then
        info "Using cached connections from $file ($proto)"
        echo "$cached_data"
        return 0
    fi
    
    info "Parsing $file ($proto)"
    local output=""
    
    # Use awk for reliable column parsing (ignores extra spaces)
    while IFS= read -r line; do
        record_operation
        [[ -z "$line" ]] && continue
        
        # Awk extracts: local_addr remote_addr state_hex inode (columns 2,3,4,10)
        local fields
        fields=$(echo "$line" | awk '{
            if (NF >= 10) {
                gsub(/^[ \t]+|[ \t]+$/, "", $2); gsub(/^[ \t]+|[ \t]+$/, "", $3);
                gsub(/^[ \t]+|[ \t]+$/, "", $4); gsub(/^[ \t]+|[ \t]+$/, "", $10);
                print $2 "|" $3 "|" $4 "|" $10
            }
        }')
        
        if [[ -z "$fields" ]]; then continue; fi
        
        local local_addr remote_addr state_hex inode
        IFS='|' read -r local_addr remote_addr state_hex inode <<< "$fields"
        
        local local_ip_hex local_port_hex remote_ip_hex remote_port_hex
        IFS=':' read -r local_ip_hex local_port_hex <<< "$local_addr"
        IFS=':' read -r remote_ip_hex remote_port_hex <<< "$remote_addr"
        
        local local_port remote_port state
        local_port=$(hex_to_dec "$local_port_hex")
        remote_port=$(hex_to_dec "$remote_port_hex")
        
        if [[ "$proto" == "tcp" ]]; then
            state="${TCP_STATES[$state_hex]:-UNKNOWN}"
        else
            state="${UDP_STATES[$state_hex]:-UNCONNECTED}"
        fi
        
        local local_ip remote_ip
        if [[ "$family" == "ipv4" ]]; then
            local_ip=$(hex_to_ipv4 "$local_ip_hex")
            remote_ip=$(hex_to_ipv4 "$remote_ip_hex")
        else
            local_ip=$(hex_to_ipv6 "$local_ip_hex")
            remote_ip=$(hex_to_ipv6 "$remote_ip_hex")
        fi
        
        local process=""
        if [[ "$(safe_get 'SHOW_PROCESSES')" == "true" ]]; then
            process=$(get_process_by_inode "$inode")
        fi
        
        output+="${proto:0:3}|${family}|${state}|${local_ip}|${local_port}|${remote_ip}|${remote_port}|${inode}|${process}"$'\n'
        
    done < <(tail -n +2 "$file" 2>/dev/null || true)
    
    cache_connections "$file" "$family" "$proto" "$output"
    echo "$output"
}

# Filter connections (added family/proto filters)
filter_connections() {
    while IFS='|' read -r proto_type family state local_ip local_port remote_ip remote_port inode process; do
        record_operation
        
        # State filter
        local filter_states=("${FILTER_STATES[@]}")
        if [[ ${#filter_states[@]} -gt 0 ]]; then
            local state_match=false
            for filter_state in "${filter_states[@]}"; do
                if [[ "$state" == "$filter_state" ]]; then
                    state_match=true
                    break
                fi
            done
            [[ "$state_match" == "false" ]] && continue
        fi
        
        # Port filter
        local filter_port="$(safe_get 'FILTER_PORT')"
        if [[ -n "$filter_port" ]]; then
            if [[ "$local_port" != "$filter_port" ]] && [[ "$remote_port" != "$filter_port" ]]; then
                continue
            fi
        fi
        
        # Local IP filter
        local filter_local_ip="$(safe_get 'FILTER_LOCAL_IP')"
        if [[ -n "$filter_local_ip" ]]; then
            if ! ip_matches_filter "$local_ip" "$filter_local_ip" "$family"; then
                continue
            fi
        fi
        
        # Remote IP filter
        local filter_remote_ip="$(safe_get 'FILTER_REMOTE_IP')"
        if [[ -n "$filter_remote_ip" ]]; then
            if ! ip_matches_filter "$remote_ip" "$filter_remote_ip" "$family"; then
                continue
            fi
        fi
        
        # IP version filter
        if [[ "$(safe_get 'FILTER_IPV4')" == "true" ]] && [[ "$family" != "ipv4" ]]; then
            continue
        fi
        if [[ "$(safe_get 'FILTER_IPV6')" == "true" ]] && [[ "$family" != "ipv6" ]]; then
            continue
        fi
        
        echo "$proto_type|$family|$state|$local_ip|$local_port|$remote_ip|$remote_port|$inode|$process"
    done
}

# Get all connections (now includes UDP if enabled)
get_all_connections() {
    local output=""
    {
        if [[ "$(safe_get 'SHOW_UDP')" == "true" ]]; then
            parse_proto_file "/proc/net/udp" "ipv4" "udp"
            parse_proto_file "/proc/net/udp6" "ipv6" "udp"
        fi
        parse_proto_file "/proc/net/tcp" "ipv4" "tcp"
        parse_proto_file "/proc/net/tcp6" "ipv6" "tcp"
    } | filter_connections
}

# Statistics (added UDP/TCP split; fixed empty state handling)
get_connection_stats() {
    local total=0 tcp=0 udp=0 ipv4=0 ipv6=0
    declare -A state_count=() process_count=()
    
    while IFS='|' read -r proto_type family state local_ip local_port remote_ip remote_port inode process; do
        # Skip malformed lines
        [[ -z "$proto_type" || -z "$family" || -z "$state" ]] && continue
        
        ((total++))
        
        if [[ "$proto_type" == "tcp" ]]; then
            ((tcp++))
        else
            ((udp++))
        fi
        
        if [[ "$family" == "ipv4" ]]; then
            ((ipv4++))
        else
            ((ipv6++))
        fi
        
        # Safe state count (skip if still empty after check)
        if [[ -n "$state" ]]; then
            state_count["$state"]=$((state_count["$state"] + 1))
        fi
        
        if [[ -n "$process" ]] && [[ "$process" != "unknown" ]]; then
            process_count["$process"]=$((process_count["$process"] + 1))
        fi
    done
    
    echo "total:$total"
    echo "tcp:$tcp"
    echo "udp:$udp"
    echo "ipv4:$ipv4"
    echo "ipv6:$ipv6"
    
    local state
    for state in "${!state_count[@]}"; do
        echo "state:$state:${state_count[$state]}"
    done
    
    local process
    for process in "${!process_count[@]}"; do
        echo "process:$process:${process_count[$process]}"
    done
}

# Alert check
check_alert() {
    local stats="$1" alert_state="$2" threshold="$3"
    local count=$(echo "$stats" | grep "^state:$alert_state:" | cut -d: -f3 || echo "0")
    if [[ "$count" -gt "$threshold" ]]; then
        echo -e "${RED}ALERT: $alert_state connections ($count) exceed threshold ($threshold)!${RESET}"
        return 0
    fi
    return 1
}

# Display colored state (unchanged)
colored_state() {
    local state="$1"
    local color="${STATE_COLORS[$state]:-$WHITE}"
    printf "%b%s%b" "$color" "$state" "$RESET"
}

# Display functions (updated for proto/family)
display_connections_table() {
    local connections_file="$1"
    
    echo -e "\n${BOLD}ACTIVE CONNECTIONS (TCP/UDP)${RESET}"
    
    if [[ "$(safe_get 'SHOW_PROCESSES')" == "true" ]]; then
        printf "%b%-6s %-6s %-15s %-25s %-25s %-30s%b\n" "$BOLD" "Proto" "Family" "State" "Local Address" "Remote Address" "Process" "$RESET"
        printf '%120s\n' | tr ' ' '-'
    else
        printf "%b%-6s %-6s %-15s %-25s %-25s%b\n" "$BOLD" "Proto" "Family" "State" "Local Address" "Remote Address" "$RESET"
        printf '%85s\n' | tr ' ' '-'
    fi
    
    while IFS='|' read -r proto_type family state local_ip local_port remote_ip remote_port inode process; do
        local local_addr="$local_ip:$local_port"
        local remote_addr="$remote_ip:$remote_port"
        if [[ "$(safe_get 'SHOW_PROCESSES')" == "true" ]]; then
            printf "%-6s %-6s " "${proto_type^^}" "${family^^}"
            colored_state "$state"
            printf " %-25s %-25s %-30s\n" \
                "$local_addr" \
                "$remote_addr" \
                "${process:0:30}"
        else
            printf "%-6s %-6s " "${proto_type^^}" "${family^^}"
            colored_state "$state"
            printf " %-25s %-25s\n" \
                "$local_addr" \
                "$remote_addr"
        fi
    done < "$connections_file"
}

display_summary() {
    local connections_file="$1"
    local stats
    
    stats=$(get_connection_stats < "$connections_file")
    
    local total=$(echo "$stats" | grep "^total:" | cut -d: -f2)
    local tcp=$(echo "$stats" | grep "^tcp:" | cut -d: -f2)
    local udp=$(echo "$stats" | grep "^udp:" | cut -d: -f2)
    local ipv4=$(echo "$stats" | grep "^ipv4:" | cut -d: -f2)
    local ipv6=$(echo "$stats" | grep "^ipv6:" | cut -d: -f2)
    
    echo -e "\n${BOLD}Summary:${RESET} $total total connections ($tcp TCP, $udp UDP; $ipv4 IPv4, $ipv6 IPv6)"
    
    local state_lines=$(echo "$stats" | grep "^state:")
    if [[ -n "$state_lines" ]]; then
        echo -n "By state: "
        local first=true
        while IFS= read -r line; do
            local state=$(echo "$line" | cut -d: -f2)
            local count=$(echo "$line" | cut -d: -f3)
            
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo -n ", "
            fi
            
            colored_state "$state"
            echo -n ": $count"
        done <<< "$state_lines"
        echo
    fi
}

display_connections_json() {
    local connections_file="$1"
    
    echo "["
    local first=true
    while IFS='|' read -r proto_type family state local_ip local_port remote_ip remote_port inode process; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        
        cat << EOF
    {
        "proto": "${proto_type^^}",
        "family": "${family^^}",
        "state": "$state",
        "local_ip": "$local_ip",
        "local_port": $local_port,
        "remote_ip": "$remote_ip",
        "remote_port": $remote_port,
        "inode": "$inode",
        "process": "$process"
    }
EOF
    done < "$connections_file"
    echo "]"
}

display_connections_csv() {
    local connections_file="$1"
    echo "Proto,Family,State,Local IP,Local Port,Remote IP,Remote Port,Inode,Process"
    while IFS='|' read -r proto_type family state local_ip local_port remote_ip remote_port inode process; do
        # Escape commas in fields
        local_ip="${local_ip//,/&#44;}"
        remote_ip="${remote_ip//,/&#44;}"
        process="${process//,/&#44;}"
        echo "\"${proto_type^^}\",\"${family^^}\",\"$state\",\"$local_ip\",$local_port,\"$remote_ip\",$remote_port,\"$inode\",\"$process\""
    done < "$connections_file"
}

display_statistics() {
    local connections_file="$1"
    local stats
    
    stats=$(get_connection_stats < "$connections_file")
    
    echo -e "\n${BOLD}DETAILED CONNECTION STATISTICS${RESET}"
    printf '%55s\n' | tr ' ' '='
    
    local total=$(echo "$stats" | grep "^total:" | cut -d: -f2)
    local tcp=$(echo "$stats" | grep "^tcp:" | cut -d: -f2)
    local udp=$(echo "$stats" | grep "^udp:" | cut -d: -f2)
    local ipv4=$(echo "$stats" | grep "^ipv4:" | cut -d: -f2)
    local ipv6=$(echo "$stats" | grep "^ipv6:" | cut -d: -f2)
    
    echo "Generated at: $(date -Iseconds)"
    echo "Total connections: $total"
    echo "TCP connections: $tcp"
    echo "UDP connections: $udp"
    echo "IPv4 connections: $ipv4"
    echo "IPv6 connections: $ipv6"
    
    echo -e "\n${BOLD}Connections by State:${RESET}"
    printf '%30s\n' | tr ' ' '-'
    
    while IFS=':' read -r _ state count; do
        printf "%-20s: %d\n" "$(colored_state "$state")" "$count"
    done < <(echo "$stats" | grep "^state:" | sort -t: -k3 -nr)
    
    # Top processes
    local process_count=0
    echo -e "\n${BOLD}Connections by Process (Top $MAX_DISPLAY_PROCESSES):${RESET}"
    printf '%55s\n' | tr ' ' '-'
    
    while IFS=':' read -r _ process count && [[ "$process_count" -lt "$MAX_DISPLAY_PROCESSES" ]]; do
        printf "%-45s: %d\n" "$process" "$count"
        ((process_count++))
    done < <(echo "$stats" | grep "^process:" | sort -t: -k3 -nr)
}

# Watch mode (added TTY check for clear)
watch_mode() {
    local interval="${1:-2}"
    local last_connections=""
    local iteration=0
    
    trap 'echo -e "\n${YELLOW}Monitoring stopped.${RESET}"; exit 0' SIGINT SIGTERM
    
    echo -e "${BOLD}Watching connections${RESET} (refresh every ${interval}s). Press Ctrl+C to stop."
    echo "Started at: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    
    local is_tty=true
    [[ ! -t 1 ]] && is_tty=false
    
    while true; do
        ((iteration++))
        
        local current_connections
        current_connections=$(get_all_connections)
        local current_count=$(echo "$current_connections" | grep -c . || echo "0")
        
        if [[ "$is_tty" == "true" ]]; then
            clear
        fi
        echo -e "${BOLD}[$(date '+%H:%M:%S')] Iteration: $iteration | Connections: $current_count${RESET}"
        printf '%65s\n' | tr ' ' '-'
        echo
        
        local tmp_file=$(mktemp)
        echo "$current_connections" > "$tmp_file"
        
        if [[ "$(safe_get 'JSON_OUTPUT')" == "true" ]]; then
            display_connections_json "$tmp_file"
        elif [[ "$(safe_get 'CSV_OUTPUT')" == "true" ]]; then
            display_connections_csv "$tmp_file"
        else
            display_connections_table "$tmp_file"
            display_summary "$tmp_file"
        fi
        
        if [[ "$(safe_get 'SHOW_STATS')" == "true" ]]; then
            display_statistics "$tmp_file"
        fi
        
        if [[ "$(safe_get 'ALERT_MODE')" == "true" ]]; then
            local alert_state="$(safe_get 'ALERT_STATE')"
            local alert_threshold="$(safe_get 'ALERT_THRESHOLD')"
            if [[ -n "$alert_state" && "$alert_threshold" -gt 0 ]]; then
                check_alert "$(get_connection_stats < "$tmp_file")" "$alert_state" "$alert_threshold"
            fi
        fi
        
        rm -f "$tmp_file"
        sleep "$interval"
    done
}

# Output to file (unchanged)
output_to_file() {
    local content="$1" file="$2"
    if ! echo "$content" > "$file"; then
        die "Failed to write output to: $file"
    fi
    echo "Output written to: $file"
}

# Parse command line arguments (added new options)
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "${1:-}" in
            --json) JSON_OUTPUT=true ;;
            --csv) CSV_OUTPUT=true ;;
            --udp) SHOW_UDP=true ;;
            --listen) FILTER_STATES+=("LISTEN") ;;
            --established) FILTER_STATES+=("ESTABLISHED") ;;
            --timewait) FILTER_STATES+=("TIME_WAIT") ;;
            --closewait) FILTER_STATES+=("CLOSE_WAIT") ;;
            --finwait) FILTER_STATES+=("FIN_WAIT1" "FIN_WAIT2") ;;
            --count) SHOW_COUNT=true ;;
            --processes) SHOW_PROCESSES=true ;;
            --port) 
                FILTER_PORT="${2:-}"
                if [[ -z "$FILTER_PORT" ]]; then
                    die "Port number required for --port"
                fi
                validate_port "$FILTER_PORT"
                shift
                ;;
            --local-ip)
                FILTER_LOCAL_IP="${2:-}"
                if [[ -z "$FILTER_LOCAL_IP" ]]; then
                    die "IP address required for --local-ip"
                fi
                validate_ip_cidr "$FILTER_LOCAL_IP"
                shift
                ;;
            --remote-ip)
                FILTER_REMOTE_IP="${2:-}"
                if [[ -z "$FILTER_REMOTE_IP" ]]; then
                    die "IP address required for --remote-ip"
                fi
                validate_ip_cidr "$FILTER_REMOTE_IP"
                shift
                ;;
            --ipv4) FILTER_IPV4=true ;;
            --ipv6) FILTER_IPV6=true ;;
            --watch)
                WATCH_MODE=true
                if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                    REFRESH_INTERVAL="$2"
                    validate_interval "$REFRESH_INTERVAL"
                    shift
                fi
                ;;
            --stats) SHOW_STATS=true ;;
            --alert-state)
                ALERT_STATE="${2:-}"
                if [[ -z "$ALERT_STATE" ]]; then
                    die "State required for --alert-state"
                fi
                ALERT_MODE=true
                shift
                ;;
            --alert-threshold)
                ALERT_THRESHOLD="${2:-}"
                if [[ -z "$ALERT_THRESHOLD" ]]; then
                    die "Threshold required for --alert-threshold"
                fi
                validate_threshold "$ALERT_THRESHOLD"
                shift
                ;;
            --output) 
                OUTPUT_FILE="${2:-}"
                if [[ -z "$OUTPUT_FILE" ]]; then
                    die "Filename required for --output"
                fi
                shift 
                ;;
            --verbose|-v) VERBOSE=true ;;
            --version) show_version ;;
            --help) show_help; exit 0 ;;
            *) 
                if [[ -n "${1:-}" ]]; then
                    die "Unknown option: $1\nUse --help for usage information"
                fi
                ;;
        esac
        shift
    done
}

# Main function (updated for new features)
main() {
    load_config
    parse_arguments "$@"
    check_requirements
    
    if [[ "$WATCH_MODE" == "true" ]]; then
        watch_mode "$REFRESH_INTERVAL"
        return 0
    fi
    
    local connections
    connections=$(get_all_connections)
    
    if [[ -z "$connections" ]]; then
        echo "No matching connections found."
        return 0
    fi
    
    local output_content=""
    local tmp_file=$(mktemp)
    echo "$connections" > "$tmp_file"
    
    local stats
    stats=$(get_connection_stats < "$tmp_file")
    
    if [[ "$ALERT_MODE" == "true" ]]; then
        local alert_state="$(safe_get 'ALERT_STATE')"
        local alert_threshold="$(safe_get 'ALERT_THRESHOLD')"
        if [[ -n "$alert_state" && "$alert_threshold" -gt 0 ]]; then
            check_alert "$stats" "$alert_state" "$alert_threshold"
        fi
    fi
    
    if [[ "$SHOW_COUNT" == "true" ]]; then
        local total=$(echo "$stats" | grep "^total:" | cut -d: -f2)
        local tcp=$(echo "$stats" | grep "^tcp:" | cut -d: -f2)
        local udp=$(echo "$stats" | grep "^udp:" | cut -d: -f2)
        local ipv4=$(echo "$stats" | grep "^ipv4:" | cut -d: -f2)
        local ipv6=$(echo "$stats" | grep "^ipv6:" | cut -d: -f2)
        
        echo "Counts: total=$total tcp=$tcp udp=$udp IPv4=$ipv4 IPv6=$ipv6"
        
        local state_lines=$(echo "$stats" | grep "^state:")
        if [[ -n "$state_lines" ]]; then
            echo -n "By state: "
            local first=true
            while IFS= read -r line; do
                local state=$(echo "$line" | cut -d: -f2)
                local count=$(echo "$line" | cut -d: -f3)
                
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo -n ", "
                fi
                
                colored_state "$state"
                echo -n ": $count"
            done <<< "$state_lines"
            echo
        fi
        
    elif [[ "$SHOW_STATS" == "true" ]]; then
        output_content=$(display_statistics "$tmp_file")
    elif [[ "$JSON_OUTPUT" == "true" ]]; then
        output_content=$(display_connections_json "$tmp_file")
    elif [[ "$CSV_OUTPUT" == "true" ]]; then
        output_content=$(display_connections_csv "$tmp_file")
    else
        output_content=$(display_connections_table "$tmp_file"
        display_summary "$tmp_file")
    fi
    
    if [[ -n "$output_content" ]]; then
        if [[ -n "$OUTPUT_FILE" ]]; then
            output_to_file "$output_content" "$OUTPUT_FILE"
        else
            echo "$output_content"
        fi
    fi
    
    rm -f "$tmp_file"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "\n${BOLD}Performance Metrics:${RESET}"
        get_performance_metrics
    fi
}

# Run main function only if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
