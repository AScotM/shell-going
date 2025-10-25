#!/bin/bash

# TCP Connection Monitor - Shell Script Version
# Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections

# Color codes for output
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
WHITE='\033[37m'
RESET='\033[0m'

# TCP state mappings
declare -A TCP_STATES=(
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

# State colors
declare -A STATE_COLORS=(
    ["LISTEN"]="$GREEN"
    ["ESTABLISHED"]="$CYAN"
    ["TIME_WAIT"]="$YELLOW"
    ["CLOSE_WAIT"]="$RED"
    ["FIN_WAIT1"]="$MAGENTA"
    ["FIN_WAIT2"]="$MAGENTA"
)

# Configuration
REFRESH_INTERVAL=2
SHOW_PROCESSES=false
JSON_OUTPUT=false
SHOW_COUNT=false
SHOW_STATS=false
WATCH_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --json) JSON_OUTPUT=true ;;
        --listen) FILTER_STATES+=("LISTEN") ;;
        --established) FILTER_STATES+=("ESTABLISHED") ;;
        --timewait) FILTER_STATES+=("TIME_WAIT") ;;
        --closewait) FILTER_STATES+=("CLOSE_WAIT") ;;
        --finwait) FILTER_STATES+=("FIN_WAIT1" "FIN_WAIT2") ;;
        --count) SHOW_COUNT=true ;;
        --processes) SHOW_PROCESSES=true ;;
        --port) FILTER_PORT="$2"; shift ;;
        --local-ip) FILTER_LOCAL_IP="$2"; shift ;;
        --remote-ip) FILTER_REMOTE_IP="$2"; shift ;;
        --ipv4) FILTER_IPV4=true ;;
        --ipv6) FILTER_IPV6=true ;;
        --watch) WATCH_MODE=true; [[ $2 =~ ^[0-9]+$ ]] && REFRESH_INTERVAL="$2" && shift ;;
        --stats) SHOW_STATS=true ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options: --json, --listen, --established, --count, --processes, --watch, --stats, etc."
            exit 0
            ;;
    esac
    shift
done

# Convert hex to decimal
hex_to_dec() {
    printf "%d" "0x$1"
}

# Convert hex IPv4 to dotted decimal
hex_to_ipv4() {
    local hex="$1"
    local ip parts=()
    for ((i=6; i>=0; i-=2)); do
        parts+=("$(hex_to_dec "${hex:$i:2}")")
    done
    printf "%d.%d.%d.%d" "${parts[@]}"
}

# Convert hex IPv6 (simplified)
hex_to_ipv6() {
    local hex="$1"
    echo "::1"  # Simplified for this example
}

# Get process name from inode (simplified)
get_process_by_inode() {
    local inode="$1"
    # Simple implementation - in real script you'd scan /proc
    echo "unknown"
}

# Parse TCP file
parse_tcp_file() {
    local file="$1" family="$2"
    [ ! -f "$file" ] && return
    
    tail -n +2 "$file" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        
        local fields=($line)
        [ ${#fields[@]} -lt 10 ] && continue
        
        local local_addr="${fields[1]}" remote_addr="${fields[2]}"
        local state_hex="${fields[3]}" inode="${fields[9]}"
        
        IFS=':' read -r local_ip_hex local_port_hex <<< "$local_addr"
        IFS=':' read -r remote_ip_hex remote_port_hex <<< "$remote_addr"
        
        local local_port=$(hex_to_dec "$local_port_hex")
        local remote_port=$(hex_to_dec "$remote_port_hex")
        local state="${TCP_STATES[$state_hex]:-UNKNOWN}"
        
        if [ "$family" = "ipv4" ]; then
            local local_ip=$(hex_to_ipv4 "$local_ip_hex")
            local remote_ip=$(hex_to_ipv4 "$remote_ip_hex")
            local proto="IPv4"
        else
            local local_ip=$(hex_to_ipv6 "$local_ip_hex")
            local remote_ip=$(hex_to_ipv6 "$remote_ip_hex")
            local proto="IPv6"
        fi
        
        local process=""
        [ "$SHOW_PROCESSES" = true ] && process=$(get_process_by_inode "$inode")
        
        echo "$proto|$state|$local_ip|$local_port|$remote_ip|$remote_port|$process"
    done
}

# Filter connections
filter_connections() {
    while IFS='|' read -r proto state local_ip local_port remote_ip remote_port process; do
        # State filter
        if [ ${#FILTER_STATES[@]} -gt 0 ]; then
            local match=false
            for s in "${FILTER_STATES[@]}"; do
                [ "$state" = "$s" ] && match=true && break
            done
            [ "$match" = false ] && continue
        fi
        
        # Port filter
        [ -n "$FILTER_PORT" ] && [ "$local_port" != "$FILTER_PORT" ] && [ "$remote_port" != "$FILTER_PORT" ] && continue
        
        # IP version filter
        [ "$FILTER_IPV4" = true ] && [ "$proto" != "IPv4" ] && continue
        [ "$FILTER_IPV6" = true ] && [ "$proto" != "IPv6" ] && continue
        
        echo "$proto|$state|$local_ip|$local_port|$remote_ip|$remote_port|$process"
    done
}

# Get all connections
get_connections() {
    {
        parse_tcp_file "/proc/net/tcp" "ipv4"
        parse_tcp_file "/proc/net/tcp6" "ipv6"
    } | filter_connections
}

# Get statistics
get_stats() {
    local total=0 ipv4=0 ipv6=0
    declare -A state_count
    
    while IFS='|' read -r proto state _ _ _ _ _; do
        ((total++))
        [ "$proto" = "IPv4" ] && ((ipv4++)) || ((ipv6++))
        ((state_count[$state]++))
    done
    
    echo "Total: $total"
    echo "IPv4: $ipv4"
    echo "IPv6: $ipv6"
    for state in "${!state_count[@]}"; do
        echo "State:$state:${state_count[$state]}"
    done
}

# Display colored state
colored_state() {
    local state="$1"
    local color="${STATE_COLORS[$state]:-$WHITE}"
    printf "${color}%s${RESET}" "$state"
}

# Display summary
display_summary() {
    local stats=$(get_stats)
    local total=$(echo "$stats" | grep "^Total:" | cut -d' ' -f2)
    local ipv4=$(echo "$stats" | grep "^IPv4:" | cut -d' ' -f2)
    local ipv6=$(echo "$stats" | grep "^IPv6:" | cut -d' ' -f2)
    
    echo -e "\nSummary: $total total connections ($ipv4 IPv4, $ipv6 IPv6)"
    
    # FIXED: Proper colored state output
    local state_lines=$(echo "$stats" | grep "^State:")
    if [ -n "$state_lines" ]; then
        echo -n "By state: "
        local first=true
        while IFS= read -r line; do
            local state=$(echo "$line" | cut -d: -f2)
            local count=$(echo "$line" | cut -d: -f3)
            if [ "$first" = true ]; then
                first=false
            else
                echo -n ", "
            fi
            colored_state "$state"
            echo -n ": $count"
        done <<< "$state_lines"
        echo  # final newline
    fi
}

# Display table
display_table() {
    echo -e "\nACTIVE TCP CONNECTIONS:"
    printf "%-5s %-15s %-25s %-25s\n" "Proto" "State" "Local Address" "Remote Address"
    echo "----------------------------------------------------------------------"
    
    while IFS='|' read -r proto state local_ip local_port remote_ip remote_port process; do
        local color="${STATE_COLORS[$state]:-$WHITE}"
        printf "%-5s ${color}%-15s${RESET} %-25s %-25s\n" \
            "$proto" "$state" "$local_ip:$local_port" "$remote_ip:$remote_port"
    done
}

# Display JSON
display_json() {
    echo "["
    local first=true
    while IFS='|' read -r proto state local_ip local_port remote_ip remote_port process; do
        [ "$first" = true ] && first=false || echo ","
        cat <<EOF
  {
    "proto": "$proto",
    "state": "$state",
    "local_ip": "$local_ip",
    "local_port": $local_port,
    "remote_ip": "$remote_ip", 
    "remote_port": $remote_port,
    "process": "$process"
  }
EOF
    done
    echo "]"
}

# Main execution
if [ "$WATCH_MODE" = true ]; then
    echo "Watch mode not fully implemented in this simplified version"
    exit 0
fi

connections=$(get_connections)

if [ -z "$connections" ]; then
    echo "No connections found"
    exit 0
fi

if [ "$SHOW_COUNT" = true ]; then
    display_summary <<< "$connections"
elif [ "$SHOW_STATS" = true ]; then
    get_stats <<< "$connections"
elif [ "$JSON_OUTPUT" = true ]; then
    display_json <<< "$connections"
else
    display_table <<< "$connections"
    display_summary <<< "$connections"
fi
