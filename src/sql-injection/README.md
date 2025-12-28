# SQL Injection Attack Module (using sqlmap)

MITRE ATT&CK: T1190 - Exploit Public-Facing Application

## Files

| File                   | Description                         |
| ---------------------- | ----------------------------------- |
| `config.json`          | Configuration (target, credentials) |
| `sqli_attack.sh`       | Wrapper script for sqlmap           |
| `suricata.local.rules` | Detection rules                     |

## Requirements (Kali Linux)

```bash
# sqlmap (pre-installed on Kali)
apt install sqlmap

# jq for JSON parsing
apt install jq
```

## Usage

```bash
# Make executable
chmod +x sqli_attack.sh

# Run attack
./sqli_attack.sh
```

## What it does

1. Reads config from `config.json`
2. Logs into DVWA with credentials
3. Sets security level (low/medium/high)
4. Runs sqlmap against `/vulnerabilities/sqli/?id=1`
5. Extracts databases, tables, and user data

## Configuration

Edit `config.json`:
```json
{
    "target": {
        "host": "dvwa.local",
        "port": 80
    },
    "credentials": {
        "username": "admin",
        "password": "password"
    }
}
```

## Detection

Deploy rules to Suricata:
```bash
sudo cp suricata.local.rules /var/lib/suricata/rules/local.rules
sudo suricatasc -c "reload-rules"
```
