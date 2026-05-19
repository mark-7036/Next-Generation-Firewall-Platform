import subprocess
import logging
import threading
import time
import ipaddress
import re
import json
import os
import socket
from collections import deque
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

try:
    import pydivert
    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False

# Use absolute paths so logs/data are always written next to this module
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TRAFFIC_LOG_PATH = os.path.join(BASE_DIR, "firewall_traffic.log")

logging.basicConfig(
    filename=TRAFFIC_LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class FirewallApp:
    BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklists.json")
    RULES_FILE = os.path.join(BASE_DIR, "rules.txt")
    LOG_FILE = os.path.join(BASE_DIR, "firewall_gui.log")
    STATUS_FILE = os.path.join(BASE_DIR, "firewall_status.json")
    UPTIME_FILE = os.path.join(BASE_DIR, "firewall_uptime.json")
    HISTORY_FILE = os.path.join(BASE_DIR, "firewall_history.json")
    HISTORY_FULL_FILE = os.path.join(BASE_DIR, "firewall_history_full.log")
    MAX_TRAFFIC_EVENTS = 200

    telemetry_blocklist = {
        "settings-win.data.microsoft.com",
        "vortex.data.microsoft.com",
        "telemetry.microsoft.com",
        "watson.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com",
        "wes.df.telemetry.microsoft.com",
        "sls.update.microsoft.com.akadns.net",
        "fe2.update.microsoft.com.akadns.net",
        "diagnostics.support.microsoft.com",
        "statsfe2.update.microsoft.com.akadns.net",
        "corpext.msitadfs.glbdns2.microsoft.com",
        "compatexchange.cloudapp.net",
        "a-0001.a-msedge.net",
        "statsfe2.ws.microsoft.com",
        "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.ppe.telemetry.microsoft.com",
        "watson.live.com",
        "watson.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "feedback.windows.com",
        "feedback.microsoft-hohm.com",
        "feedback.search.microsoft.com",
        "rad.msn.com",
        "preview.msn.com",
        "ad.doubleclick.net",
        "ads.msn.com",
        "ads1.msads.net",
        "ads1.msn.com",
        "a.ads1.msn.com",
        "a.ads2.msn.com",
        "adnexus.net",
        "adnxs.com",
        "az361816.vo.msecnd.net",
        "az512334.vo.msecnd.net"
    }

    malware_signatures = [
        b'\x90\x90\x90',
        b'badstuff',
    ]

    sensitive_data_patterns = [
        re.compile(rb'\b4[0-9]{12}(?:[0-9]{3})?\b'),
        re.compile(rb'\b5[1-5][0-9]{14}\b'),
    ]

    content_filters = [
        b'adult', b'porn', b'torrent', b'xxx'
    ]

    def __init__(self):
        self.lock = threading.RLock()
        self.is_firewall_enabled = True
        self.sniff_thread = None
        self.stop_sniff = threading.Event()
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.blocked_protocols = set()
        self.dpi_patterns = set()
        self.custom_rules = []
        self.log = []
        self.packet_stats = {"allowed": 0, "blocked": 0}
        self.custom_blocklist = set()
        self.blocked_domains = set()
        self.interactive_mode = False
        self.telemetry_block_enabled = True
        self.interactive_pending = {}
        self.interactive_decisions = {}
        self.use_win_divert = HAS_PYDIVERT
        self.traffic_events = deque(maxlen=self.MAX_TRAFFIC_EVENTS)
        self.history = []
        self.start_time = time.time()
        self.last_malware = None
        self.last_content = None
        self.last_telemetry = None
        self.spi_state_table = {}  # From Base1.py
        self.load_blocklists()
        self.load_rules()
        self.load_log()
        self.load_firewall_status()
        self.load_uptime()
        self.load_history()
        self.app_start_time = time.time()
        self.uptime_accumulated = 0
        self.last_enabled_time = None
        self.is_firewall_enabled = True 
        if self.is_firewall_enabled:
            self.last_enabled_time = time.time()
        self.refresh_domains_timer = None
        self.refresh_blocked_domains_firewall()

    def save_rules(self):
        with open(self.RULES_FILE, "w") as f:
            for rule in self.custom_rules:
                f.write(rule + "\n")

    def load_rules(self):
        if os.path.exists(self.RULES_FILE):
            with open(self.RULES_FILE, "r") as f:
                self.custom_rules = [line.strip() for line in f if line.strip()]
        else:
            self.custom_rules = []

    def start_monitoring(self, iface=None):
        self.stop_sniff.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_thread_func, args=(iface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_monitoring(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.stop_sniff.set()
            self.sniff_thread.join(timeout=1.0)

    def _sniff_thread_func(self, iface):
        sniff(
            prn=self.process_packet,
            filter="ip or ip6",
            store=0,
            iface=iface,
            stop_filter=lambda _: self.stop_sniff.is_set()
        )

    def get_full_log(self):
        # Return the persistent history log
        if os.path.exists("firewall_history_full.log"):
            with open("firewall_history_full.log", "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def save_log(self):
        with open(self.LOG_FILE, "w") as f:
            for entry in self.log:
                f.write(entry + "\n")

    def load_log(self):
        if os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, "r") as f:
                self.log = [line.strip() for line in f if line.strip()]
        else:
            self.log = []

    def load_blocklists(self):
        if os.path.exists(self.BLOCKLIST_FILE):
            with open(self.BLOCKLIST_FILE, "r") as f:
                data = json.load(f)
            self.blocked_ips = set(data.get("blocked_ips", []))
            self.blocked_ports = set(str(port) for port in data.get("blocked_ports", []))
            self.blocked_protocols = set(data.get("blocked_protocols", []))
            # Convert strings back to bytes
            self.dpi_patterns = set(
                p.encode('utf-8') if not isinstance(p, bytes) else p
                for p in data.get("dpi_patterns", [])
            )
            self.custom_blocklist = set(data.get("custom_blocklist", []))
            self.blocked_domains = set(data.get("blocked_domains", []))
        else:
            self.blocked_ips = set()
            self.blocked_ports = set()
            self.blocked_protocols = set()
            self.dpi_patterns = set()
            self.custom_blocklist = set()
            self.blocked_domains = set()

    def save_firewall_status(self):
        with open(self.STATUS_FILE, "w") as f:
            json.dump({"enabled": self.is_firewall_enabled}, f)

    def load_firewall_status(self):
        if os.path.exists(self.STATUS_FILE):
            with open(self.STATUS_FILE, "r") as f:
                data = json.load(f)
                self.is_firewall_enabled = data.get("enabled", True)
        else:
            self.is_firewall_enabled = True
            self.save_firewall_status()

    def save_uptime(self):
        with open(self.UPTIME_FILE, "w") as f:
            json.dump({"start_time": self.start_time}, f)

    def load_uptime(self):
        if os.path.exists(self.UPTIME_FILE):
            with open(self.UPTIME_FILE, "r") as f:
                data = json.load(f)
                self.start_time = data.get("start_time", time.time())
        else:
            self.start_time = time.time()
            self.save_uptime()

    def save_history(self):
        with open(self.HISTORY_FILE, "w") as f:
            json.dump(self.history, f)

    def load_history(self):
        if os.path.exists(self.HISTORY_FILE):
            with open(self.HISTORY_FILE, "r") as f:
                self.history = json.load(f)
        else:
            self.history = []

    # --- Logging ---

    def log_message(self, message):
        with self.lock:
            timestamp = time.strftime("%H:%M:%S")
            msg = f"[{timestamp}] {message}"
            self.log.append(msg)
            logging.info(message)
            self.save_log()
            with open("firewall_history_full.log", "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    def get_log(self):
        with self.lock:
            return self.log[-50:]

    def export_logs(self, filepath):
        with open(filepath, "w") as f:
            for entry in self.log:
                f.write(entry + "\n")
        self.log_message(f"Exported logs to {filepath}")

    # --- Interactive Mode ---

    def set_interactive_mode(self, enabled: bool):
        self.interactive_mode = enabled
        self.log_message(f"Interactive mode {'enabled' if enabled else 'disabled'}.")

    def set_telemetry_block(self, enabled: bool):
        self.telemetry_block_enabled = enabled
        self.log_message(f"Telemetry block {'enabled' if enabled else 'disabled'}.")

    def should_prompt(self, process_name):
        return self.interactive_mode

    def wait_for_interactive_decision(self, process_name):
        return "block_once"

    def set_interactive_decision(self, process_name, decision):
        pass

    # --- Blocklist Methods ---

    def add_blocked_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.log_message(f"Invalid IP: {ip}")
            return
        with self.lock:
            if ip in self.blocked_ips:
                self.log_message(f"IP already in block list: {ip}")
                return
            self.blocked_ips.add(ip)
            self.save_blocklists()
        # Add Windows Firewall rules (inbound and outbound)
        for direction in ("in", "out"):
            rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", f"dir={direction}", "action=block",
                    f"remoteip={ip}", "profile=any"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.log_message(f"Firewall rule added: {rule_name}")
            except subprocess.CalledProcessError as e:
                if "An object with the same key already exists" in e.stderr:
                    self.log_message(f"Firewall rule already exists: {rule_name}")
                else:
                    self.log_message(f"Error adding firewall rule for IP {ip}: {e.stderr.strip()}")
        self.log_message(f"Added IP to block list: {ip}")

    def unblock_ip(self, ip):
        with self.lock:
            if ip not in self.blocked_ips:
                self.log_message(f"IP not in block list: {ip}")
                return
            self.blocked_ips.remove(ip)
            self.save_blocklists()
        # Remove Windows Firewall rules (inbound and outbound)
        for direction in ("in", "out"):
            rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.log_message(f"Firewall rule removed: {rule_name}")
            except subprocess.CalledProcessError as e:
                if "No rules match the specified criteria" in e.stderr:
                    self.log_message(f"No firewall rule found to remove: {rule_name}")
                else:
                    self.log_message(f"Error removing firewall rule for IP {ip}: {e.stderr.strip()}")
        self.log_message(f"Unblocked IP: {ip}")

    def add_blocked_port(self, port):
        port = str(port).strip()
        if not port.isdigit():
            self.log_message(f"Invalid port: {port}")
            return
        with self.lock:
            if port in self.blocked_ports:
                self.log_message(f"Port already in block list: {port}")
                return
            self.blocked_ports.add(port)
            self.save_blocklists()
        self._apply_port_block_rules(port)
        self.log_message(f"Added Port to block list: {port}")

    def _apply_port_block_rules(self, port):
        for proto in ("TCP", "UDP"):
            for direction, port_type in (("in", "localport"), ("out", "remoteport")):
                rule_name = f"Block_{proto}_Port_{port}_{direction}"
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block",
                        f"protocol={proto}", f"{port_type}={port}", "profile=any"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule added: {rule_name}")
                except subprocess.CalledProcessError as e:
                    if "An object with the same key already exists" in e.stderr:
                        self.log_message(f"Firewall rule already exists: {rule_name}")
                    else:
                        self.log_message(f"Error adding firewall rule for port {port}: {e.stderr.strip()}")

    def _remove_port_block_rules(self, port):
        for proto in ("TCP", "UDP"):
            for direction in ("in", "out"):
                rule_name = f"Block_{proto}_Port_{port}_{direction}"
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule removed: {rule_name}")
                except subprocess.CalledProcessError as e:
                    if "No rules match the specified criteria" in e.stderr:
                        self.log_message(f"No firewall rule found to remove: {rule_name}")
                    else:
                        self.log_message(f"Error removing firewall rule for port {port}: {e.stderr.strip()}")

        # Fallback cleanup: remove any matching rules by criteria in case an
        # older rule name or duplicate rule survived the name-based delete.
        for proto in ("TCP", "UDP"):
            for direction, port_type in (("in", "localport"), ("out", "remoteport")):
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"protocol={proto}", f"dir={direction}", f"{port_type}={port}"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule criteria removed: {proto} {direction} {port}")
                except subprocess.CalledProcessError as e:
                    if "No rules match the specified criteria" in e.stderr:
                        self.log_message(f"No criteria-based firewall rule found for port: {port}")
                    else:
                        self.log_message(f"Error removing criteria-based firewall rule for port {port}: {e.stderr.strip()}")

    def unblock_port(self, port):
        port = str(port)
        with self.lock:
            if port not in self.blocked_ports:
                self.log_message(f"Port not in block list: {port}")
                return
            self.blocked_ports.remove(port)
            self.save_blocklists()
        self._remove_port_block_rules(port)
        self.log_message(f"Unblocked Port: {port}")

    def add_blocked_protocol(self, proto):
        proto = proto.upper()
        if proto not in {"TCP", "UDP", "ICMP"}:
            self.log_message(f"Unsupported protocol: {proto}")
            return
        with self.lock:
            if proto in self.blocked_protocols:
                self.log_message(f"Protocol already in block list: {proto}")
                return
            self.blocked_protocols.add(proto)
            self.save_blocklists()
        proto_arg = "ICMPv4" if proto == "ICMP" else proto
        for direction in ("in", "out"):
            rule_name = f"Block_Proto_{proto}_{direction}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", f"dir={direction}", "action=block",
                    f"protocol={proto_arg}", "profile=any"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.log_message(f"Firewall rule added: {rule_name}")
            except subprocess.CalledProcessError as e:
                if "An object with the same key already exists" in e.stderr:
                    self.log_message(f"Firewall rule already exists: {rule_name}")
                else:
                    self.log_message(f"Error adding firewall rule for protocol {proto}: {e.stderr.strip()}")
        self.log_message(f"Added Protocol to block list: {proto}")
        
    def unblock_protocol(self, proto):
        proto = proto.upper()
        with self.lock:
            if proto not in self.blocked_protocols:
                self.log_message(f"Protocol not in block list: {proto}")
                return
            self.blocked_protocols.remove(proto)
            self.save_blocklists()
        for direction in ("in", "out"):
            rule_name = f"Block_Proto_{proto}_{direction}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.log_message(f"Firewall rule removed: {rule_name}")
            except subprocess.CalledProcessError as e:
                if "No rules match the specified criteria" in e.stderr:
                    self.log_message(f"No firewall rule found to remove: {rule_name}")
                else:
                    self.log_message(f"Error removing firewall rule for protocol {proto}: {e.stderr.strip()}")
        self.log_message(f"Unblocked Protocol: {proto}")

    # --- DPI/Content Filtering ---

    def add_dpi_pattern(self, pattern):
        if isinstance(pattern, str):
            pattern = pattern.encode()
        with self.lock:
            if pattern in self.dpi_patterns:
                self.log_message(f"DPI pattern already in block list: {pattern}")
                return
            self.dpi_patterns.add(pattern)
            self.save_blocklists()
        self.log_message(f"Added DPI pattern to block list: {pattern}")

    def unblock_dpi_pattern(self, pattern):
        if isinstance(pattern, str):
            pattern = pattern.encode('utf-8')
        with self.lock:
            if pattern not in self.dpi_patterns:
                self.log_message(f"DPI pattern not in block list: {pattern}")
                return
            self.dpi_patterns.remove(pattern)
            self.save_blocklists()
        self.log_message(f"Unblocked DPI pattern: {pattern}")

    # --- DNS Filtering ---

    def block_domain_connections(self, domain):
        try:
            ips = set()
            for res in socket.getaddrinfo(domain, None):
                ip = res[4][0]
                ips.add(ip)
        except Exception as e:
            self.log_message(f"Failed to resolve domain {domain}: {e}")
            return

        for ip in ips:
            for direction in ("in", "out"):
                rule_name = f"Block_{domain}_{ip}_{direction}"
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block",
                        f"remoteip={ip}", "profile=any"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule added: {rule_name}")
                except subprocess.CalledProcessError as e:
                    if "An object with the same key already exists" in e.stderr:
                        self.log_message(f"Firewall rule already exists: {rule_name}")
                    else:
                        self.log_message(f"Error adding firewall rule for {domain} ({ip}): {e.stderr.strip()}")

    def unblock_domain_connections(self, domain):
        try:
            ips = set()
            for res in socket.getaddrinfo(domain, None):
                ip = res[4][0]
                ips.add(ip)
        except Exception as e:
            self.log_message(f"Failed to resolve domain {domain}: {e}")
            return

        for ip in ips:
            for direction in ("in", "out"):
                rule_name = f"Block_{domain}_{ip}_{direction}"
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule removed: {rule_name}")
                except subprocess.CalledProcessError as e:
                    if "No rules match the specified criteria" in e.stderr:
                        self.log_message(f"No firewall rule found to remove: {rule_name}")
                    else:
                        self.log_message(f"Error removing firewall rule for {domain} ({ip}): {e.stderr.strip()}")

    def refresh_blocked_domains_firewall(self):
        """Periodically refresh firewall rules for all blocked domains (to catch changing IPs)."""
        with self.lock:
            domains = list(self.blocked_domains)
        for domain in domains:
            self.unblock_domain_connections(domain)
            self.block_domain_connections(domain)
        if hasattr(self, "refresh_domains_timer") and self.refresh_domains_timer:
            self.refresh_domains_timer.cancel()
        self.refresh_domains_timer = threading.Timer(60, self.refresh_blocked_domains_firewall)
        self.refresh_domains_timer.daemon = True
        self.refresh_domains_timer.start()
    
    def stop_refresh_domains_timer(self):
        if hasattr(self, "refresh_domains_timer") and self.refresh_domains_timer:
            self.refresh_domains_timer.cancel()
            self.refresh_domains_timer = None

    def add_blocked_domain(self, domain):
        domain = domain.lower().strip()
        with self.lock:
            if domain in self.blocked_domains:
                self.log_message(f"Domain already in block list: {domain}")
                return
            self.blocked_domains.add(domain)
            self.save_blocklists()
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                if any(domain in line for line in lines):
                    self.log_message(f"Domain already in hosts file: {domain}")
                else:
                    with open(hosts_path, "a", encoding="utf-8") as f:
                        f.write(f"127.0.0.1 {domain}\n")
                    self.log_message(f"Blocked domain at network level (hosts): {domain}")
            else:
                self.log_message(f"Hosts file not found: {hosts_path}")
        except Exception as e:
            self.log_message(f"Failed to block domain in hosts file: {domain} ({e})")
        self.block_domain_connections(domain)

    def remove_blocked_domain(self, domain):
        domain = domain.lower().strip()
        with self.lock:
            if domain not in self.blocked_domains:
                self.log_message(f"Domain not in block list: {domain}")
                return
            self.blocked_domains.remove(domain)
            self.save_blocklists()
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(hosts_path, "w", encoding="utf-8") as f:
                    for line in lines:
                        if domain not in line:
                            f.write(line)
                self.log_message(f"Unblocked domain at network level (hosts): {domain}")
            else:
                self.log_message(f"Hosts file not found: {hosts_path}")
        except Exception as e:
            self.log_message(f"Failed to unblock domain in hosts file: {domain} ({e})")
        self.unblock_domain_connections(domain)

    # --- Telemetry/Malware/Content Filtering ---

    def is_telemetry_domain(self, domain):
        return self.telemetry_block_enabled and (domain.lower() in self.telemetry_blocklist)

    def scan_packet_for_malware(self, payload):
        for sig in self.malware_signatures:
            if sig in payload:
                self.last_malware = time.strftime("%Y-%m-%d %H:%M:%S")
                return True
        return False

    def scan_packet_for_content(self, payload):
        for word in self.content_filters:
            if word in payload:
                self.last_content = time.strftime("%Y-%m-%d %H:%M:%S")
                return True
        return False

    # --- History ---

    def log_status_change(self, status):
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "blocked": self.packet_stats.get("blocked", 0),
            "allowed": self.packet_stats.get("allowed", 0)
        }
        self.history.append(entry)
        if len(self.history) > 100:
            self.history = self.history[-100:]
        self.save_history()

    def get_history(self, n=10):
        return self.history[-n:]

    # --- WinDivert-based packet filtering ---

    def _sniff_packets_win_divert(self):
        print("WinDivert packet filter started (admin required)")
        with pydivert.WinDivert("true") as w:
            for packet in w:
                if self.stop_sniff.is_set():
                    break
                with self.lock:
                    blocked = False
                    if not self.is_firewall_enabled:
                        blocked = False
                    else:
                        # Block by IP
                        if packet.src_addr in self.blocked_ips or packet.dst_addr in self.blocked_ips:
                            blocked = True
                        # Block by port
                        if str(packet.src_port) in self.blocked_ports or str(packet.dst_port) in self.blocked_ports:
                            blocked = True
                        # Block by protocol
                        if packet.protocol.name.upper() in self.blocked_protocols:
                            blocked = True
                        # --- DPI pattern check ---
                        try:
                            payload = bytes(packet.payload)
                            for pattern in self.dpi_patterns:
                                pattern_bytes = pattern.encode() if isinstance(pattern, str) else pattern
                                if pattern_bytes in payload:
                                    blocked = True
                                    self.log_message(f"Blocked by DPI pattern: {pattern}")
                                    break
                        except Exception as e:
                            self.log_message(f"DPI check error: {e}")
                event = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "src": str(packet.src_addr),
                    "sport": str(packet.src_port),
                    "dst": str(packet.dst_addr),
                    "dport": str(packet.dst_port),
                    "proto": str(packet.protocol.name),
                    "action": "Blocked" if blocked else "Allowed"
                }
                with self.lock:
                    self.traffic_events.appendleft(event)
                if blocked:
                    self.packet_stats["blocked"] += 1
                    self.log_message(f"Blocked packet: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port} [{packet.protocol.name}]")
                    continue  
                else:
                    self.packet_stats["allowed"] += 1
                    self.log_message(f"Allowed packet: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port} [{packet.protocol.name}]")
                    w.send(packet)

    # --- Scapy-based packet sniffing (monitor only, Base1.py logic) ---

    def _process_packet_gui(self, packet):
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
                src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else ""
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else ""
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
                src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else ""
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else ""
            else:
                return

            event = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src": str(src_ip),
                "sport": str(src_port),
                "dst": str(dst_ip),
                "dport": str(dst_port),
                "proto": str(proto),
                "action": ""  # You can fill this with "Allowed"/"Blocked" if you wish
            }
            with self.lock:
                self.traffic_events.appendleft(event)
        except Exception:
            pass

    def save_blocklists(self):
        data = {
            "blocked_ips": list(getattr(self, "blocked_ips", [])),
            "blocked_ports": list(getattr(self, "blocked_ports", [])),
            "blocked_protocols": list(getattr(self, "blocked_protocols", [])),
            "dpi_patterns": [p.decode('utf-8', errors='replace') if isinstance(p, bytes) else str(p) for p in getattr(self, "dpi_patterns", [])],
            "custom_blocklist": list(getattr(self, "custom_blocklist", [])),
            "blocked_domains": list(getattr(self, "blocked_domains", [])),
        }
        with open(self.BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def add_custom_rule(self, rule):
        with self.lock:
            if rule not in self.custom_rules:
                self.custom_rules.append(rule)
                self.save_rules()
                tokens = rule.strip().split()
                try:
                    if len(tokens) == 3 and tokens[0].upper() == "BLOCK":
                        if tokens[1].upper() == "IP":
                            ip = tokens[2]
                            ipaddress.ip_address(ip)
                            self.add_blocked_ip(ip)
                        elif tokens[1].upper() == "PORT":
                            port = tokens[2]
                            if port.isdigit():
                                self.add_blocked_port(port)
                            else:
                                self.log_message(f"Invalid port in custom rule: {port}")
                        elif tokens[1].upper() == "PROTOCOL":
                            self.add_blocked_protocol(tokens[2])
                        else:
                            self.log_message(f"Unknown custom rule type: {rule}")
                    else:
                        self.log_message(f"Unsupported custom rule format: {rule}")
                except Exception as e:
                    self.log_message(f"Error processing custom rule '{rule}': {e}")
                self.save_blocklists()
                self.log_message(f"Custom rule added: {rule}")

    def remove_custom_rule(self, idx):
        with self.lock:
            if 0 <= idx < len(self.custom_rules):
                rule = self.custom_rules.pop(idx)
                self.save_rules()
                tokens = rule.strip().split()
                if len(tokens) == 3 and tokens[0].upper() == "BLOCK":
                    if tokens[1].upper() == "IP":
                        ip = tokens[2]
                        self.unblock_ip(ip)
                    elif tokens[1].upper() == "PORT":
                        port = tokens[2]
                        self.unblock_port(port)
                    elif tokens[1].upper() == "PROTOCOL":
                        proto = tokens[2]
                        self.unblock_protocol(proto)
                self.save_blocklists()
                self.log_message(f"Custom rule removed: {rule}")

    def enable_firewall(self):
        with self.lock:
            self.is_firewall_enabled = True
            if self.last_enabled_time is None:
                self.last_enabled_time = time.time()
            self.save_uptime()
            self.save_firewall_status()
            self.log_status_change("enabled")

            # Re-apply all Windows Firewall rules for current blocklists

            # Block IPs
            for ip in self.blocked_ips:
                for direction in ("in", "out"):
                    rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block",
                        f"remoteip={ip}", "profile=any"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Block Ports
            for port in self.blocked_ports:
                self._apply_port_block_rules(port)

            # Block Protocols
            for proto in self.blocked_protocols:
                proto_arg = "ICMPv4" if proto == "ICMP" else proto
                for direction in ("in", "out"):
                    rule_name = f"Block_Proto_{proto}_{direction}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block",
                        f"protocol={proto_arg}", "profile=any"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        self.log_message("Firewall enabled and all block rules re-applied.")

    def disable_firewall(self):
        with self.lock:
         self.is_firewall_enabled = False
        if self.last_enabled_time:
            self.uptime_accumulated += time.time() - self.last_enabled_time
            self.last_enabled_time = None

            for ip in list(self.blocked_ips):
                for direction in ("in", "out"):
                    rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            for port in list(self.blocked_ports):
                self._remove_port_block_rules(port)

            for proto in list(self.blocked_protocols):
                for direction in ("in", "out"):
                    rule_name = f"Block_Proto_{proto}_{direction}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        self.log_message("Firewall disabled and all applied rules reverted.")

    def toggle_firewall(self):
        with self.lock:
            self.is_firewall_enabled = not self.is_firewall_enabled
            if self.is_firewall_enabled:
                self.start_time = time.time()
                self.save_uptime()
                self.log_status_change("enabled")
            else:
                self.log_status_change("disabled")
            self.save_firewall_status()
        state = "enabled" if self.is_firewall_enabled else "disabled"
        self.log_message(f"Firewall {state}.")

    def export_rules(self, filepath):
        try:
            with open(filepath, "w") as f:
                for rule in self.custom_rules:
                    f.write(rule + "\n")
            self.log_message(f"Exported rules to {filepath}")
        except Exception as e:
            self.log_message(f"Error exporting rules: {e}")

    def import_rules(self, filepath):
        try:
            with open(filepath, "r") as f:
                for line in f:
                    rule = line.strip()
                    if rule and rule not in self.custom_rules:
                        try:
                            self.add_custom_rule(rule)
                        except Exception as e:
                            self.log_message(f"Error importing rule '{rule}': {e}")
            self.log_message(f"Imported rules from {filepath}")
            self.enable_firewall()
        except Exception as e:
            self.log_message(f"Error importing rules: {e}")
        
    def clear_logs(self):
        with self.lock:
            self.log.clear()
        with open(self.LOG_FILE, "w") as f:
            pass  

    def clear_custom_rules(self):
        with self.lock:
            for rule in list(self.custom_rules):
                tokens = rule.strip().split()
                if len(tokens) == 3 and tokens[0].upper() == "BLOCK":
                    if tokens[1].upper() == "IP":
                        ip = tokens[2]
                        self.unblock_ip(ip)
                    elif tokens[1].upper() == "PORT":
                        port = tokens[2]
                        self.unblock_port(port)
                    elif tokens[1].upper() == "PROTOCOL":
                        proto = tokens[2]
                        self.unblock_protocol(proto)
            self.custom_rules.clear()
            self.save_rules()
            self.save_blocklists()
            self.log_message("All custom rules cleared.")

    def get_packet_stats(self):
        with self.lock:
            return dict(self.packet_stats)

    def get_blocklists(self):
        with self.lock:
            return {
                "blocked_ips": list(self.blocked_ips),
                "blocked_ports": list(self.blocked_ports),
                "blocked_protocols": list(self.blocked_protocols),
                "dpi_patterns": list(self.dpi_patterns),
                "blocked_domains": list(self.blocked_domains),  # DNS filtering
            }

    def get_status(self):
        return "Enabled" if self.is_firewall_enabled else "Disabled"

    def get_recent_log(self, n=10):
        with self.lock:
            return self.log[-n:]

    def get_stats(self):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        total_time = time.time() - self.app_start_time
        uptime = self.uptime_accumulated
        if self.is_firewall_enabled and self.last_enabled_time:
            uptime += time.time() - self.last_enabled_time
        if total_time > 0:
            uptime_percent = round((uptime / total_time) * 100, 2)
        else:
            uptime_percent = 100.0
        hours, remainder = divmod(int(uptime), 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"Up for {hours}h {minutes}m {seconds}s"
        response_time = round(1.0 + (time.time() % 2), 2)
        history = [
            (h["timestamp"], h["status"].capitalize(), f"Blocked: {h['blocked']} Allowed: {h['allowed']}")
            for h in self.get_history(10)
        ]
        security = []
        if self.last_malware:
            security.append((f"Malware detected at {self.last_malware}", False))
        else:
            security.append(("No malware detected by scan", True))
        if self.last_content:
            security.append((f"Sensitive content detected at {self.last_content}", False))
        else:
            security.append(("No sensitive content detected", True))
        if self.telemetry_block_enabled:
            if self.last_telemetry:
                security.append((f"Telemetry blocked at {self.last_telemetry}", True))
            else:
                security.append(("Telemetry blocking enabled", True))
        else:
            security.append(("Telemetry blocking disabled", False))
        security.append(("Interactive mode " + ("enabled" if self.interactive_mode else "disabled"), self.interactive_mode))
        blocked_attempts = self.packet_stats.get("blocked", 0)
        allowed_attempts = self.packet_stats.get("allowed", 0)
        firewall_status = "Enabled" if self.is_firewall_enabled else "Disabled"
        rules_applied = len(self.custom_rules)
        if blocked_attempts > 0:
            security.append((f"{blocked_attempts} packets blocked", False))
        return {
            "firewall_status": firewall_status,
            "last_update": now,
            "rules_applied": rules_applied,
            "packets_blocked": blocked_attempts,
            "packets_allowed": allowed_attempts,
            "uptime": uptime_str,
            "uptime_percent": uptime_percent, 
            "response_time": response_time,
            "history": history,
            "security": security,
            "blocked_ips": list(self.blocked_ips),
            "blocked_ports": list(self.blocked_ports),
            "blocked_protocols": list(self.blocked_protocols),
            "dpi_patterns": list(self.dpi_patterns),
            "custom_rules": list(self.custom_rules),
            "blocked_domains": list(self.blocked_domains), 
        }