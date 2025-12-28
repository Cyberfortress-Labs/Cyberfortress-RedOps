# ============================================================================
# CYBERFORTRESS REDOPS - Zeek Signatures for C2 Detection
# File: c2_detection.sig
# ============================================================================

# C2 Beacon: GET /beacon
signature cf-c2-beacon-uri {
    ip-proto == tcp
    dst-port == 80
    payload /.*GET.*\/beacon/
    event "C2 Beacon Pattern Detected (GET /beacon)"
}

# C2 Panel: /gate.php
signature cf-c2-gate-php {
    ip-proto == tcp
    dst-port == 80
    payload /.*\/gate\.php/
    event "C2 Gate.php Pattern Detected"
}

# Malware User-Agent
signature cf-c2-malwarebot {
    ip-proto == tcp
    dst-port == 80
    payload /.*User-Agent:.*MalwareBot/
    event "C2 Suspicious User-Agent (MalwareBot)"
}

# C2 Header: X-Bot-ID
signature cf-c2-xbotid {
    ip-proto == tcp
    dst-port == 80
    payload /.*X-Bot-ID:/
    event "C2 X-Bot-ID Header Detected"
}

# C2 Beacon body
signature cf-c2-beacon-body {
    ip-proto == tcp
    dst-port == 80
    payload /.*type=beacon/
    event "C2 Beacon POST Body Detected"
}

# Metasploit port
signature cf-c2-metasploit {
    ip-proto == tcp
    dst-port == 4444
    event "C2 Connection to Metasploit Port (4444)"
}

# Common C2 port
signature cf-c2-port-5555 {
    ip-proto == tcp
    dst-port == 5555
    event "C2 Connection to Common C2 Port (5555)"
}

# Empire port
signature cf-c2-empire {
    ip-proto == tcp
    dst-port == 8443
    event "C2 Connection to Empire Port (8443)"
}
