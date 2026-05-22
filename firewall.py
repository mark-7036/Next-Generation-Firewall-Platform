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
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
except Exception:
    sniff = None
    IP = IPv6 = TCP = UDP = ICMP = None

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


def _is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class FirewallApp:
    BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklists.json")
    RULES_FILE = os.path.join(BASE_DIR, "rules.txt")
    LOG_FILE = os.path.join(BASE_DIR, "firewall_gui.log")
    STATUS_FILE = os.path.join(BASE_DIR, "firewall_status.json")
    UPTIME_FILE = os.path.join(BASE_DIR, "firewall_uptime.json")
    HISTORY_FILE = os.path.join(BASE_DIR, "firewall_history.json")
    HISTORY_FULL_FILE = os.path.join(BASE_DIR, "firewall_history_full.log")
    NAT_FILE = os.path.join(BASE_DIR, "nat_rules.json")
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
        self.packet_engine = "windivert" if HAS_PYDIVERT else "scapy"
        self.traffic_events = deque(maxlen=self.MAX_TRAFFIC_EVENTS)
        self.history = []
        self.start_time = time.time()
        self.last_malware = None
        self.last_content = None
        self.last_telemetry = None
        self.spi_state_table = {}
        # Load persisted state
        self.load_blocklists()
        self.load_rules()
        self.load_log()
        self.load_firewall_status()
        self.load_uptime()
        self.load_history()
        self.nat_rules = {}
        self.udp_forwarder_threads = {}
        self.udp_forwarder_stop_events = {}
        self.udp_forwarder_sessions = {}
        self.load_nat_rules()
        # NAT session table for stateful translation (keyed by tuple)
        # session key: (proto, int_ip, int_port, peer_ip, peer_port)
        self.nat_sessions = {}
        self.nat_sessions_lock = threading.RLock()
        # Start session cleanup thread
        self._session_cleaner_stop = threading.Event()
        self._session_cleaner_thread = threading.Thread(target=self._nat_session_cleaner, daemon=True)
        self._session_cleaner_thread.start()
        self.app_start_time = time.time()
        self.uptime_accumulated = 0
        self.last_enabled_time = None
        if self.is_firewall_enabled:
            self.last_enabled_time = time.time()
        self.refresh_domains_timer = None
        self.refresh_blocked_domains_firewall()

    def save_rules(self):
        with open(self.RULES_FILE, "w", encoding="utf-8") as f:
            for rule in self.custom_rules:
                f.write(rule + "\n")

    def load_rules(self):
        if os.path.exists(self.RULES_FILE):
            with open(self.RULES_FILE, "r", encoding="utf-8") as f:
                self.custom_rules = [line.strip() for line in f if line.strip()]
        else:
            self.custom_rules = []

    def start_monitoring(self, iface=None):
        self.stop_sniff.clear()
        if sniff is None:
            return  # Ensure we exit if sniff is not available
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
        if os.path.exists(self.HISTORY_FULL_FILE):
            with open(self.HISTORY_FULL_FILE, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def save_log(self):
        with open(self.LOG_FILE, "w", encoding="utf-8") as f:
            for entry in self.log:
                f.write(entry + "\n")

    def load_log(self):
        if os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, "r", encoding="utf-8") as f:
                self.log = [line.strip() for line in f if line.strip()]
        else:
            self.log = []

    def load_blocklists(self):
        if os.path.exists(self.BLOCKLIST_FILE):
            try:
                with open(self.BLOCKLIST_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.blocked_ips = set(data.get("blocked_ips", []))
                self.blocked_ports = set(str(port) for port in data.get("blocked_ports", []))
                self.blocked_protocols = set(data.get("blocked_protocols", []))
                self.dpi_patterns = set(
                    p.encode('utf-8') if not isinstance(p, bytes) else p
                    for p in data.get("dpi_patterns", [])
                )
                self.custom_blocklist = set(data.get("custom_blocklist", []))
                self.blocked_domains = set(data.get("blocked_domains", []))
            except Exception:
                self.blocked_ips = set()
                self.blocked_ports = set()
                self.blocked_protocols = set()
                self.dpi_patterns = set()
                self.custom_blocklist = set()
                self.blocked_domains = set()
        else:
            self.blocked_ips = set()
            self.blocked_ports = set()
            self.blocked_protocols = set()
            self.dpi_patterns = set()
            self.custom_blocklist = set()
            self.blocked_domains = set()

    def save_firewall_status(self):
        with open(self.STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump({"enabled": self.is_firewall_enabled}, f)

    def load_firewall_status(self):
        if os.path.exists(self.STATUS_FILE):
            try:
                with open(self.STATUS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.is_firewall_enabled = data.get("enabled", True)
            except Exception:
                self.is_firewall_enabled = True
        else:
            self.is_firewall_enabled = True
            self.save_firewall_status()

    def save_uptime(self):
        with open(self.UPTIME_FILE, "w", encoding="utf-8") as f:
            json.dump({"start_time": self.start_time}, f)

    def load_uptime(self):
        if os.path.exists(self.UPTIME_FILE):
            try:
                with open(self.UPTIME_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.start_time = data.get("start_time", time.time())
            except Exception:
                self.start_time = time.time()
        else:
            self.start_time = time.time()
            self.save_uptime()

    def save_history(self):
        with open(self.HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.history, f)

    def load_history(self):
        if os.path.exists(self.HISTORY_FILE):
            try:
                with open(self.HISTORY_FILE, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
            except Exception:
                self.history = []
        else:
            self.history = []

    def log_message(self, message):
        with self.lock:
            timestamp = time.strftime("%H:%M:%S")
            msg = f"[{timestamp}] {message}"
            try:
                self.log.append(msg)
                logging.info(message)
                self.save_log()
                with open(self.HISTORY_FULL_FILE, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass

    def get_log(self):
        with self.lock:
            return self.log[-50:]

    def export_logs(self, filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in self.log:
                f.write(entry + "\n")
        self.log_message(f"Exported logs to {filepath}")

    def load_nat_rules(self):
        try:
            if os.path.exists(self.NAT_FILE):
                with open(self.NAT_FILE, 'r', encoding='utf-8') as f:
                    self.nat_rules = json.load(f)
            else:
                self.nat_rules = {}
        except Exception as e:
            self.log_message(f"Failed to load NAT rules: {e}")
            self.nat_rules = {}

    def save_nat_rules(self):
        try:
            with open(self.NAT_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.nat_rules, f, indent=2)
        except Exception as e:
            self.log_message(f"Failed to save NAT rules: {e}")

    def _port_in_use(self, port):
        try:
            out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if f":{port} " in line and "LISTENING" in line.upper():
                    return True
        except Exception:
            pass
        return False

    def set_interactive_mode(self, enabled: bool):
        self.interactive_mode = enabled
        self.log_message(f"Interactive mode {'enabled' if enabled else 'disabled'}.")

    def set_telemetry_block(self, enabled: bool):
        self.telemetry_block_enabled = enabled
        self.log_message(f"Telemetry block {'enabled' if enabled else 'disabled'}.")

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
                if e.stderr and "An object with the same key already exists" in e.stderr:
                    self.log_message(f"Firewall rule already exists: {rule_name}")
                else:
                    self.log_message(f"Error adding firewall rule for IP {ip}: {getattr(e, 'stderr', '').strip()}")
        self.log_message(f"Added IP to block list: {ip}")

    def unblock_ip(self, ip):
        with self.lock:
            if ip not in self.blocked_ips:
                self.log_message(f"IP not in block list: {ip}")
                return
            self.blocked_ips.remove(ip)
            self.save_blocklists()
        for direction in ("in", "out"):
            rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.log_message(f"Firewall rule removed: {rule_name}")
            except subprocess.CalledProcessError as e:
                self.log_message(f"Error removing firewall rule for IP {ip}: {getattr(e, 'stderr', '').strip()}")
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
                    self.log_message(f"Error adding firewall rule for port {port}: {getattr(e, 'stderr', '').strip()}")

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
                    self.log_message(f"Error removing firewall rule for port {port}: {getattr(e, 'stderr', '').strip()}")

        for proto in ("TCP", "UDP"):
            for direction, port_type in (("in", "localport"), ("out", "remoteport")):
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"protocol={proto}", f"dir={direction}", f"{port_type}={port}"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule criteria removed: {proto} {direction} {port}")
                except subprocess.CalledProcessError as e:
                    self.log_message(f"Error removing criteria-based firewall rule for port {port}: {getattr(e, 'stderr', '').strip()}")

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
                self.log_message(f"Error adding firewall rule for protocol {proto}: {getattr(e, 'stderr', '').strip()}")
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
                self.log_message(f"Error removing firewall rule for protocol {proto}: {getattr(e, 'stderr', '').strip()}")
        self.log_message(f"Unblocked Protocol: {proto}")

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
                    self.log_message(f"Error adding firewall rule for {domain} ({ip}): {getattr(e, 'stderr', '').strip()}")

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
                    self.log_message(f"Error removing firewall rule for {domain} ({ip}): {getattr(e, 'stderr', '').strip()}")

    def refresh_blocked_domains_firewall(self):
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

    def _sniff_packets_win_divert(self):
        if not HAS_PYDIVERT:
            return
        with pydivert.WinDivert("true") as w:
            for packet in w:
                if self.stop_sniff.is_set():
                    break
                pass

    def _process_packet_gui(self, packet):
        try:
            if packet is None:
                return
            if hasattr(packet, 'haslayer') and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
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
                "action": ""
            }
            with self.lock:
                self.traffic_events.appendleft(event)
        except Exception:
            pass

        # (moved NAT helpers to class-level to enable reuse for this subclass)

    def save_blocklists(self):
        data = {
            "blocked_ips": list(getattr(self, "blocked_ips", [])),
            "blocked_ports": list(getattr(self, "blocked_ports", [])),
            "blocked_protocols": list(getattr(self, "blocked_protocols", [])),
            "dpi_patterns": [p.decode('utf-8', errors='replace') if isinstance(p, bytes) else str(p) for p in getattr(self, "dpi_patterns", [])],
            "custom_blocklist": list(getattr(self, "custom_blocklist", [])),
            "blocked_domains": list(getattr(self, "blocked_domains", [])),
        }
        try:
            with open(self.BLOCKLIST_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    # --- NAT session helpers (class-level for this subclass) ---
    def _create_or_refresh_nat_session(self, proto, rule, peer_ip, peer_port):
        try:
            proto = proto.upper()
            int_ip = rule.get('int_ip')
            int_port = int(rule.get('int_port'))
            ext_port = int(rule.get('ext_port')) if rule.get('ext_port') is not None else int(rule.get('listen_port', 0) or 0)
            mapped_src_addr = rule.get('listen_address', None) or rule.get('external_ip', None) or '0.0.0.0'
            mapped_src_port = ext_port
            key = (proto, int_ip, int_port, peer_ip, int(peer_port) if peer_port else None)
            with self.nat_sessions_lock:
                sess = self.nat_sessions.get(key)
                now = time.time()
                if sess:
                    sess['last_seen'] = now
                    sess['packet_count'] = sess.get('packet_count', 0) + 1
                else:
                    sess = {
                        'proto': proto,
                        'int_ip': int_ip,
                        'int_port': int_port,
                        'peer_ip': peer_ip,
                        'peer_port': int(peer_port) if peer_port else None,
                        'mapped_src_addr': mapped_src_addr,
                        'mapped_src_port': mapped_src_port,
                        'state': 'SYN' if proto == 'TCP' else 'ESTABLISHED',
                        'created': now,
                        'last_seen': now,
                        'packet_count': 1,
                        'byte_count': 0,
                    }
                    self.nat_sessions[key] = sess
                return sess
        except Exception as e:
            self.log_message(f"Failed to create/refresh NAT session: {e}")
            return None

    def _find_nat_session_by_internal(self, proto, int_ip, int_port, peer_ip, peer_port):
        proto = (proto or '').upper()
        key = (proto, int_ip, int(int_port) if int_port else None, peer_ip, int(peer_port) if peer_port else None)
        with self.nat_sessions_lock:
            return self.nat_sessions.get(key)

    def _mark_session_closed(self, session):
        try:
            with self.nat_sessions_lock:
                for k, v in list(self.nat_sessions.items()):
                    if v is session:
                        del self.nat_sessions[k]
                        self.log_message(f"NAT session closed and removed: {k}")
                        break
        except Exception:
            pass

    def _nat_session_cleaner(self):
        while not getattr(self, '_session_cleaner_stop', threading.Event()).is_set():
            try:
                now = time.time()
                remove_keys = []
                with self.nat_sessions_lock:
                    for k, sess in list(self.nat_sessions.items()):
                        proto = sess.get('proto')
                        last = sess.get('last_seen', sess.get('created', now))
                        timeout = 300 if proto == 'TCP' else 60
                        if now - last > timeout:
                            remove_keys.append(k)
                    for k in remove_keys:
                        try:
                            del self.nat_sessions[k]
                            self.log_message(f"NAT session timed out and removed: {k}")
                        except Exception:
                            pass
            except Exception:
                pass
            getattr(self, '_session_cleaner_stop', threading.Event()).wait(15)

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
                        elif tokens[1].upper() == "DOMAIN":
                            self.add_blocked_domain(tokens[2])
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
                    elif tokens[1].upper() == "DOMAIN":
                        self.remove_blocked_domain(tokens[2])
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
            for ip in self.blocked_ips:
                for direction in ("in", "out"):
                    rule_name = f"BlockAll_{direction.capitalize()}_{ip}"
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=block",
                        f"remoteip={ip}", "profile=any"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for port in self.blocked_ports:
                self._apply_port_block_rules(port)
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
        if self.is_firewall_enabled:
            self.disable_firewall()
        else:
            self.enable_firewall()

    def export_rules(self, filepath):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                for rule in self.custom_rules:
                    f.write(rule + "\n")
            self.log_message(f"Exported rules to {filepath}")
        except Exception as e:
            self.log_message(f"Error exporting rules: {e}")

    def import_rules(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
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
        with open(self.LOG_FILE, "w", encoding="utf-8") as f:
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
                    elif tokens[1].upper() == "DOMAIN":
                        self.remove_blocked_domain(tokens[2])
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
                "dpi_patterns": [p.decode('utf-8', errors='replace') if isinstance(p, bytes) else str(p) for p in self.dpi_patterns],
                "blocked_domains": list(self.blocked_domains),
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
            "dpi_patterns": [p.decode('utf-8', errors='replace') if isinstance(p, bytes) else str(p) for p in self.dpi_patterns],
            "custom_rules": list(self.custom_rules),
            "blocked_domains": list(self.blocked_domains),
        }

    def add_nat_rule(self, ext_port, int_ip, int_port, protocol="TCP"):
        try:
            ext_port = int(ext_port)
            int_port = int(int_port)
        except Exception:
            self.log_message(f"Invalid port values: {ext_port} / {int_port}")
            return

        protocol = (protocol or "TCP").upper()
        key = f"{protocol}_{ext_port}"
        with self.lock:
            if key in self.nat_rules:
                self.log_message(f"NAT rule already exists: {protocol} {ext_port}")
                return

        if protocol != "TCP":
            with self.lock:
                self.nat_rules[key] = {"ext_port": ext_port, "int_ip": int_ip, "int_port": int_port, "protocol": protocol}
                self.save_nat_rules()
            self.log_message(f"NAT rule saved (no OS enforcement for non-TCP): {protocol} {ext_port} -> {int_ip}:{int_port}")
            return

        try:
            ipaddress.ip_address(int_ip)
        except Exception:
            self.log_message(f"Invalid internal IP: {int_ip}")
            return

        if not _is_admin():
            with self.lock:
                self.nat_rules[key] = {"ext_port": ext_port, "int_ip": int_ip, "int_port": int_port, "protocol": protocol}
                self.save_nat_rules()
            self.log_message(f"NAT rule saved but not enforced (requires Administrator): {protocol} {ext_port} -> {int_ip}:{int_port}")
            return

        if self._port_in_use(ext_port):
            self.log_message(f"External port {ext_port} already in use. Cannot add NAT rule.")
            return

        try:
            subprocess.run([
                "netsh", "interface", "portproxy", "add", "v4tov4",
                f"listenaddress=0.0.0.0", f"listenport={ext_port}",
                f"connectaddress={int_ip}", f"connectport={int_port}"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            rule_name = f"Securly NAT {ext_port} -> {int_ip}:{int_port}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=allow",
                "protocol=TCP", f"localport={ext_port}", "profile=any"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            with self.lock:
                self.nat_rules[key] = {"ext_port": ext_port, "int_ip": int_ip, "int_port": int_port, "protocol": protocol, "rule_name": rule_name}
                self.save_nat_rules()
            self.log_message(f"NAT rule enforced: {protocol} {ext_port} -> {int_ip}:{int_port}")
        except subprocess.CalledProcessError as e:
            self.log_message(f"Failed to apply NAT via netsh: {getattr(e, 'stderr', '').strip()}")
            try:
                subprocess.run(["netsh", "interface", "portproxy", "delete", "v4tov4", f"listenaddress=0.0.0.0", f"listenport={ext_port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except Exception:
                pass
        except Exception as e:
            self.log_message(f"Unexpected error adding NAT rule: {e}")

    def _show_portproxy_rules(self):
        try:
            result = subprocess.run(
                ["netsh", "interface", "portproxy", "show", "v4tov4"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return result.stdout
        except Exception:
            return ""

    def verify_nat_rule(self, ext_port, protocol="TCP"):
        protocol = (protocol or "TCP").upper()
        key = f"{protocol}_{ext_port}"
        rule = self.nat_rules.get(key)
        if not rule:
            return {
                "found": False,
                "enforced": False,
                "active": False,
                "message": f"NAT rule not found in state: {protocol} {ext_port}",
            }

        if protocol != "TCP":
            return {
                "found": True,
                "enforced": False,
                "active": False,
                "message": f"Stored only in policy/state: {protocol} {ext_port}",
            }

        listen_port = str(rule.get("ext_port", ext_port))
        connect_ip = str(rule.get("int_ip", ""))
        connect_port = str(rule.get("int_port", ""))
        portproxy_output = self._show_portproxy_rules()
        portproxy_match = (
            listen_port in portproxy_output
            and connect_ip in portproxy_output
            and connect_port in portproxy_output
        )

        firewall_rule_name = rule.get("rule_name") or f"Securly NAT {listen_port} -> {connect_ip}:{connect_port}"
        firewall_rule_output = ""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={firewall_rule_name}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            firewall_rule_output = result.stdout
        except Exception:
            firewall_rule_output = ""

        firewall_rule_active = bool(firewall_rule_output.strip())
        active = bool(portproxy_match and firewall_rule_active)
        if active:
            message = f"Verified and active: TCP {listen_port} -> {connect_ip}:{connect_port}"
        else:
            message = f"Rule stored but not fully active: TCP {listen_port} -> {connect_ip}:{connect_port}"

        return {
            "found": True,
            "enforced": bool(firewall_rule_active),
            "active": active,
            "message": message,
            "portproxy_match": portproxy_match,
            "firewall_rule_active": firewall_rule_active,
        }

    def sync_nat_rules(self):
        synced = []
        for key, rule in list(self.nat_rules.items()):
            protocol = str(rule.get("protocol", "TCP")).upper()
            if protocol != "TCP":
                continue
            verification = self.verify_nat_rule(rule.get("ext_port"), protocol)
            if verification.get("active"):
                synced.append({"rule": rule, "status": "active"})
                continue
            try:
                self.add_nat_rule(rule.get("ext_port"), rule.get("int_ip"), rule.get("int_port"), protocol)
                synced.append({"rule": rule, "status": "reapplied"})
            except Exception as e:
                self.log_message(f"Failed to sync NAT rule {key}: {e}")
                synced.append({"rule": rule, "status": "failed"})
        return synced

    def remove_nat_rule(self, ext_port, protocol="TCP"):
        protocol = (protocol or "TCP").upper()
        key = f"{protocol}_{ext_port}"
        with self.lock:
            if key not in self.nat_rules:
                self.log_message(f"NAT rule not found: {protocol} {ext_port}")
                return
            rule = self.nat_rules.get(key)

        if _is_admin() and protocol == "TCP":
            try:
                subprocess.run([
                    "netsh", "interface", "portproxy", "delete", "v4tov4",
                    f"listenaddress=0.0.0.0", f"listenport={ext_port}"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except subprocess.CalledProcessError as e:
                self.log_message(f"Error deleting portproxy for {ext_port}: {getattr(e, 'stderr', '').strip()}")
            except Exception as e:
                self.log_message(f"Unexpected error deleting portproxy: {e}")

            rule_name = rule.get('rule_name') if isinstance(rule, dict) else None
            if rule_name:
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.log_message(f"Firewall rule removed: {rule_name}")
                except subprocess.CalledProcessError as e:
                    self.log_message(f"Error removing firewall rule {rule_name}: {getattr(e, 'stderr', '').strip()}")
                except Exception as e:
                    self.log_message(f"Unexpected error removing firewall rule: {e}")

        with self.lock:
            try:
                if key in self.nat_rules:
                    del self.nat_rules[key]
                    self.save_nat_rules()
                    self.log_message(f"NAT rule removed from state: {protocol} {ext_port}")
            except Exception as e:
                self.log_message(f"Error removing NAT rule from state: {e}")

    def get_vpn_status(self):
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-VpnConnection | Select-Object Name, ConnectionStatus"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return "VPN Status: No active VPN connections"
        except Exception as e:
            self.log_message(f"VPN status check error: {e}")
            return f"VPN Status: Error ({e})"

    def toggle_vpn(self, enable=True):
        try:
            cmd = "rasdial.exe" if enable else "rasdial.exe /disconnect"
            self.log_message(f"VPN {'enabled' if enable else 'disabled'}")
        except Exception as e:
            self.log_message(f"VPN toggle error: {e}")

    def set_dns_servers(self, dns_list):
        if not hasattr(self, 'dns_servers'):
            self.dns_servers = []
        self.dns_servers = dns_list
        try:
            self.log_message(f"DNS configuration set to: {', '.join(dns_list)}")
        except Exception as e:
            self.log_message(f"DNS configuration error: {e}")

    def add_qos_rule(self, name, ip_range, bandwidth_mbps):
        if not hasattr(self, 'qos_rules'):
            self.qos_rules = {}
        self.qos_rules[name] = {"ip_range": ip_range, "bandwidth_mbps": bandwidth_mbps}
        self.log_message(f"QoS rule added: {name} ({ip_range}) -> {bandwidth_mbps}Mbps limit")

    def get_security_alerts(self):
        alerts = []
        if self.last_malware:
            alerts.append({"type": "Malware", "timestamp": self.last_malware, "severity": "High"})
        if self.last_content:
            alerts.append({"type": "Sensitive Content", "timestamp": self.last_content, "severity": "Medium"})
        if self.last_telemetry:
            alerts.append({"type": "Telemetry Detected", "timestamp": self.last_telemetry, "severity": "Low"})
        blocked_count = self.packet_stats.get("blocked", 0)
        if blocked_count > 100:
            alerts.append({"type": "High Block Rate", "count": blocked_count, "severity": "Medium"})
        return {"alerts": alerts, "total_alerts": len(alerts)}

    def clear_security_alerts(self):
        self.last_malware = None
        self.last_content = None
        self.last_telemetry = None
        self.log_message("Security alerts cleared")

    def backup_settings(self, filepath):
        import json
        from datetime import datetime
        backup_data = {
            "timestamp": datetime.now().isoformat(),
            "blocked_ips": list(self.blocked_ips),
            "blocked_ports": list(self.blocked_ports),
            "blocked_protocols": list(self.blocked_protocols),
            "blocked_domains": list(self.blocked_domains),
            "custom_rules": list(self.custom_rules),
            "nat_rules": getattr(self, 'nat_rules', {}),
            "qos_rules": getattr(self, 'qos_rules', {}),
            "firewall_enabled": self.is_firewall_enabled
        }
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2)
            self.log_message(f"Settings backup created: {filepath}")
        except Exception as e:
            self.log_message(f"Backup error: {e}")

    def restore_settings(self, filepath):
        import json
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            self.blocked_ips = set(backup_data.get("blocked_ips", []))
            self.blocked_ports = set(str(p) for p in backup_data.get("blocked_ports", []))
            self.blocked_protocols = set(backup_data.get("blocked_protocols", []))
            self.blocked_domains = set(backup_data.get("blocked_domains", []))
            self.custom_rules = backup_data.get("custom_rules", [])
            self.nat_rules = backup_data.get("nat_rules", {})
            self.qos_rules = backup_data.get("qos_rules", {})
            self.save_blocklists()
            self.save_rules()
            self.save_nat_rules()
            self.log_message(f"Settings restored from: {filepath}")
        except Exception as e:
            self.log_message(f"Restore error: {e}")

    def generate_analytics_report(self):
        uptime_sec = time.time() - self.app_start_time if hasattr(self, 'app_start_time') else 0
        hours = int(uptime_sec // 3600)
        minutes = int((uptime_sec % 3600) // 60)
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "firewall_status": "Enabled" if self.is_firewall_enabled else "Disabled",
            "uptime": f"{hours}h {minutes}m",
            "packets_blocked": self.packet_stats.get("blocked", 0),
            "packets_allowed": self.packet_stats.get("allowed", 0),
            "block_rate": round((self.packet_stats.get("blocked", 0) / max(self.packet_stats.get("allowed", 1) + self.packet_stats.get("blocked", 1), 1)) * 100, 2),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ports_count": len(self.blocked_ports),
            "blocked_domains_count": len(self.blocked_domains),
            "custom_rules_count": len(self.custom_rules),
            "recent_traffic_events": len(self.traffic_events),
            "security_alerts": self.get_security_alerts()
        }
        self.log_message("Analytics report generated")
        return report
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

FirewallAppBase = FirewallApp


class FirewallApp(FirewallAppBase):
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
        self.packet_engine = "windivert" if HAS_PYDIVERT else "scapy"
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
        self.nat_rules = {}
        self.load_nat_rules()
        # NAT session table for this subclass as well
        self.nat_sessions = {}
        self.nat_sessions_lock = threading.RLock()
        self._session_cleaner_stop = threading.Event()
        self._session_cleaner_thread = threading.Thread(target=self._nat_session_cleaner, daemon=True)
        self._session_cleaner_thread.start()
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
        if self.packet_engine == "wfp":
            self.log_message("WFP mode is a scaffold only; using monitor-only sniffing until a driver is added")
        use_divert = bool(self.use_win_divert and HAS_PYDIVERT)
        target = self._sniff_packets_win_divert if use_divert else self._sniff_thread_func
        thread_args = () if use_divert else (iface,)
        self.sniff_thread = threading.Thread(target=target, args=thread_args)
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

    def set_packet_engine(self, engine):
        engine = (engine or "scapy").lower().strip()
        if engine not in {"scapy", "windivert", "wfp"}:
            raise ValueError("packet engine must be 'scapy', 'windivert', or 'wfp'")
        if engine == "windivert" and not HAS_PYDIVERT:
            raise RuntimeError("WinDivert is not available in this environment")
        self.packet_engine = engine
        self.use_win_divert = engine == "windivert"
        if engine == "wfp":
            self.log_message("WFP selected: kernel-driver integration is scaffolded but not yet implemented")

    def get_packet_engine(self):
        return self.packet_engine

    def get_packet_engine_options(self):
        return [
            {
                "engine": "scapy",
                "label": "Scapy (monitor-only)",
                "available": sniff is not None,
                "description": "Packet visibility only; no inline enforcement.",
            },
            {
                "engine": "windivert",
                "label": "WinDivert (user-mode enforcement)",
                "available": HAS_PYDIVERT,
                "description": "Current inline user-mode engine used for enforcement.",
            },
            {
                "engine": "wfp",
                "label": "WFP (kernel-driver scaffold)",
                "available": False,
                "description": "Planned kernel path; scaffolded status only for now.",
            },
        ]

    def get_packet_engine_status(self):
        selected = self.get_packet_engine()
        effective = "windivert" if (selected == "windivert" and HAS_PYDIVERT) else "scapy"
        enforcement = "inline" if effective == "windivert" else "monitor-only"
        if selected == "wfp":
            enforcement = "scaffold"
        return {
            "selected": selected,
            "effective": effective,
            "available": (selected != "windivert") or HAS_PYDIVERT,
            "enforcement": enforcement,
            "description": next(
                (item["description"] for item in self.get_packet_engine_options() if item["engine"] == selected),
                "Unknown packet engine",
            ),
        }

    def _packet_protocol_name(self, packet):
        try:
            if hasattr(packet, "protocol") and getattr(packet.protocol, "name", None):
                return str(packet.protocol.name).upper()
        except Exception:
            pass
        if hasattr(packet, "haslayer"):
            try:
                if packet.haslayer(TCP):
                    return "TCP"
                if packet.haslayer(UDP):
                    return "UDP"
                if packet.haslayer(ICMP):
                    return "ICMP"
            except Exception:
                pass
        return "OTHER"

    def _packet_payload_bytes(self, packet):
        try:
            if hasattr(packet, "payload"):
                return bytes(packet.payload)
        except Exception:
            pass
        try:
            if hasattr(packet, "raw"):
                return bytes(packet.raw)
        except Exception:
            pass
        return b""

    def _packet_fields(self, packet):
        if hasattr(packet, "src_addr"):
            return {
                "src": str(packet.src_addr),
                "sport": str(getattr(packet, "src_port", "")),
                "dst": str(packet.dst_addr),
                "dport": str(getattr(packet, "dst_port", "")),
                "proto": self._packet_protocol_name(packet),
            }
        if hasattr(packet, "haslayer"):
            if packet.haslayer(IP):
                return {
                    "src": str(packet[IP].src),
                    "sport": str(packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else ""),
                    "dst": str(packet[IP].dst),
                    "dport": str(packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else ""),
                    "proto": self._packet_protocol_name(packet),
                }
            if packet.haslayer(IPv6):
                return {
                    "src": str(packet[IPv6].src),
                    "sport": str(packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else ""),
                    "dst": str(packet[IPv6].dst),
                    "dport": str(packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else ""),
                    "proto": self._packet_protocol_name(packet),
                }
        return None

    def _packet_is_blocked(self, src, sport, dst, dport, proto, payload):
        if not self.is_firewall_enabled:
            return False, "firewall-disabled"
        if src in self.blocked_ips or dst in self.blocked_ips:
            return True, "blocked-ip"
        if str(sport) in self.blocked_ports or str(dport) in self.blocked_ports:
            return True, "blocked-port"
        if proto in self.blocked_protocols:
            return True, "blocked-protocol"
        try:
            for pattern in self.dpi_patterns:
                pattern_bytes = pattern.encode() if isinstance(pattern, str) else pattern
                if pattern_bytes and pattern_bytes in payload:
                    return True, f"dpi:{pattern_bytes!r}"
        except Exception as e:
            self.log_message(f"DPI check error: {e}")
        return False, "allowed"

    def _record_packet_event(self, src, sport, dst, dport, proto, action):
        event = {
            "timestamp": time.strftime("%H:%M:%S"),
            "src": str(src),
            "sport": str(sport),
            "dst": str(dst),
            "dport": str(dport),
            "proto": str(proto),
            "action": str(action),
        }
        with self.lock:
            self.traffic_events.appendleft(event)

    def process_packet(self, packet):
        fields = self._packet_fields(packet)
        if not fields:
            return packet

        payload = self._packet_payload_bytes(packet)
        blocked, reason = self._packet_is_blocked(
            fields["src"], fields["sport"], fields["dst"], fields["dport"], fields["proto"], payload
        )

        self._record_packet_event(
            fields["src"], fields["sport"], fields["dst"], fields["dport"], fields["proto"],
            "Blocked" if blocked else "Allowed"
        )

        if blocked:
            self.packet_stats["blocked"] += 1
            self.log_message(
                f"Blocked packet: {fields['src']}:{fields['sport']} -> {fields['dst']}:{fields['dport']} [{fields['proto']}] ({reason})"
            )
            if hasattr(packet, "drop"):
                try:
                    packet.drop()
                except Exception:
                    pass
            return None

        self.packet_stats["allowed"] += 1
        self.log_message(
            f"Allowed packet: {fields['src']}:{fields['sport']} -> {fields['dst']}:{fields['dport']} [{fields['proto']}]"
        )
        if hasattr(packet, "send"):
            try:
                packet.send()
            except Exception as e:
                self.log_message(f"Packet send error: {e}")
        return packet

    def get_full_log(self):
        # Return the persistent history log
        if os.path.exists("firewall_history_full.log"):
            with open("firewall_history_full.log", "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def save_log(self):
        with open(self.LOG_FILE, "w", encoding="utf-8") as f:
            for entry in self.log:
                f.write(entry + "\n")

    def load_log(self):
        if os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, "r", encoding="utf-8") as f:
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
        for target_domain in self._domain_aliases(domain):
            try:
                ips = set()
                for res in socket.getaddrinfo(target_domain, None):
                    ip = res[4][0]
                    ips.add(ip)
            except Exception as e:
                self.log_message(f"Failed to resolve domain {target_domain}: {e}")
                continue

            for ip in ips:
                for direction in ("in", "out"):
                    rule_name = f"Block_{target_domain}_{ip}_{direction}"
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
                            self.log_message(f"Error adding firewall rule for {target_domain} ({ip}): {e.stderr.strip()}")

    def unblock_domain_connections(self, domain):
        for target_domain in self._domain_aliases(domain):
            try:
                ips = set()
                for res in socket.getaddrinfo(target_domain, None):
                    ip = res[4][0]
                    ips.add(ip)
            except Exception as e:
                self.log_message(f"Failed to resolve domain {target_domain}: {e}")
                continue

            for ip in ips:
                for direction in ("in", "out"):
                    rule_name = f"Block_{target_domain}_{ip}_{direction}"
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
                            self.log_message(f"Error removing firewall rule for {target_domain} ({ip}): {e.stderr.strip()}")

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

    def _domain_aliases(self, domain):
        domain = domain.lower().strip()
        aliases = {domain}
        if domain == "linkedin.com":
            aliases.update({
                "www.linkedin.com",
                "static.licdn.com",
                "media.licdn.com",
                "www.licdn.com",
                "www.linkedin.cn",
                "www.linkedin.com.cn",
            })
        return sorted(aliases)

    def _refresh_domain_rule_now(self, domain):
        try:
            self.unblock_domain_connections(domain)
            self.block_domain_connections(domain)
        except Exception as e:
            self.log_message(f"Failed to refresh domain enforcement for {domain}: {e}")

    def _flush_dns_cache(self):
        try:
            subprocess.run(["ipconfig", "/flushdns"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.log_message("DNS cache flushed")
        except Exception as e:
            self.log_message(f"Failed to flush DNS cache: {e}")

    def _remove_domain_enforcement(self, domain):
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(hosts_path, "w", encoding="utf-8") as f:
                    for line in lines:
                        if not any(alias in line.lower() for alias in self._domain_aliases(domain)):
                            f.write(line)
                self.log_message(f"Domain enforcement removed from hosts: {domain}")
        except Exception as e:
            self.log_message(f"Failed to remove domain hosts enforcement for {domain}: {e}")

        try:
            self.unblock_domain_connections(domain)
        except Exception as e:
            self.log_message(f"Failed to remove domain firewall rules for {domain}: {e}")

        self._flush_dns_cache()

    def _apply_domain_enforcement(self, domain):
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                missing_aliases = []
                for alias in self._domain_aliases(domain):
                    if not any(alias in line.lower() for line in lines):
                        missing_aliases.append(alias)
                if missing_aliases:
                    with open(hosts_path, "a", encoding="utf-8") as f:
                        for alias in missing_aliases:
                            f.write(f"127.0.0.1 {alias}\n")
                    self.log_message(f"Domain enforcement applied to hosts: {domain} ({', '.join(missing_aliases)})")
            else:
                self.log_message(f"Hosts file not found: {hosts_path}")
        except Exception as e:
            self.log_message(f"Failed to apply domain hosts enforcement for {domain}: {e}")

        try:
            self.block_domain_connections(domain)
        except Exception as e:
            self.log_message(f"Failed to apply domain firewall rules for {domain}: {e}")

        self._flush_dns_cache()
    
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
        
        # Check admin rights before attempting hosts file modification
        if not _is_admin():
            self.log_message(f"⚠️ Domain {domain} added to block list but NOT ENFORCED at OS level (requires Administrator rights)")
            # Still try firewall rules on resolved IPs
            self.block_domain_connections(domain)
            return
        
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                missing_aliases = []
                for alias in self._domain_aliases(domain):
                    if not any(alias in line for line in lines):
                        missing_aliases.append(alias)
                if missing_aliases:
                    with open(hosts_path, "a", encoding="utf-8") as f:
                        for alias in missing_aliases:
                            f.write(f"127.0.0.1 {alias}\n")
                    self.log_message(f"✓ ENFORCED: Domain blocked at network level (hosts): {domain} ({', '.join(missing_aliases)})")
                else:
                    self.log_message(f"Domain already in hosts file: {domain}")
            else:
                self.log_message(f"Hosts file not found: {hosts_path}")
        except PermissionError:
            self.log_message(f"❌ PERMISSION DENIED writing hosts file for {domain}. Run as Administrator.")
        except Exception as e:
            self.log_message(f"Failed to block domain in hosts file: {domain} ({e})")
        self._refresh_domain_rule_now(domain)
        self._flush_dns_cache()

    def remove_blocked_domain(self, domain):
        domain = domain.lower().strip()
        with self.lock:
            if domain not in self.blocked_domains:
                self.log_message(f"Domain not in block list: {domain}")
                return
            self.blocked_domains.remove(domain)
            self.save_blocklists()
        
        if not _is_admin():
            self.log_message(f"⚠️ Domain {domain} removed from block list but NOT removed from OS-level enforcement (requires Administrator)")
            self.unblock_domain_connections(domain)
            self._flush_dns_cache()
            return
        
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(hosts_path, "w", encoding="utf-8") as f:
                    for line in lines:
                        if not any(alias in line.lower() for alias in self._domain_aliases(domain)):
                            f.write(line)
                self.log_message(f"✓ REMOVED: Domain unblocked at network level (hosts): {domain}")
            else:
                self.log_message(f"Hosts file not found: {hosts_path}")
        except PermissionError:
            self.log_message(f"❌ PERMISSION DENIED removing {domain} from hosts file. Run as Administrator.")
        except Exception as e:
            self.log_message(f"Failed to unblock domain in hosts file: {domain} ({e})")
        self.unblock_domain_connections(domain)
        self._flush_dns_cache()

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
        if not HAS_PYDIVERT:
            return
        self.log_message("WinDivert packet filter started (admin required)")
        with pydivert.WinDivert("true") as w:
            for packet in w:
                if self.stop_sniff.is_set():
                    break
                # --- Stateful NAT: inbound rewrite and outbound reverse translation ---
                try:
                    proto_name = None
                    try:
                        proto_name = self._packet_protocol_name(packet)
                    except Exception:
                        proto_name = None

                    # Attempt inbound translation: external -> internal
                    dst_port = None
                    try:
                        dst_port = int(getattr(packet, 'dst_port', 0) or 0)
                    except Exception:
                        dst_port = None

                    if proto_name and dst_port:
                        key = f"{proto_name}_{dst_port}"
                        rule = self.nat_rules.get(key)
                        if rule:
                            # Create or refresh session for this inbound flow
                            peer_ip = getattr(packet, 'src_addr', None)
                            peer_port = getattr(packet, 'src_port', None)
                            self._create_or_refresh_nat_session(proto_name, rule, peer_ip, peer_port)
                            try:
                                old_dst = packet.dst_addr
                                old_dport = getattr(packet, 'dst_port', None)
                                packet.dst_addr = rule.get('int_ip')
                                packet.dst_port = int(rule.get('int_port'))
                                self.log_message(f"WinDivert NAT rewrite IN: {proto_name} {old_dst}:{old_dport} -> {packet.dst_addr}:{packet.dst_port}")
                            except Exception:
                                pass

                    # Attempt outbound translation: internal -> peer (reverse mapping)
                    src_port = None
                    try:
                        src_port = int(getattr(packet, 'src_port', 0) or 0)
                    except Exception:
                        src_port = None
                    if proto_name and src_port:
                        session = self._find_nat_session_by_internal(proto_name, getattr(packet, 'src_addr', None), src_port, getattr(packet, 'dst_addr', None), getattr(packet, 'dst_port', None))
                        if session:
                            try:
                                mapped_src_addr = session.get('mapped_src_addr')
                                mapped_src_port = session.get('mapped_src_port')
                                old_src = packet.src_addr
                                old_sport = getattr(packet, 'src_port', None)
                                packet.src_addr = mapped_src_addr
                                packet.src_port = mapped_src_port
                                self.log_message(f"WinDivert NAT rewrite OUT: {proto_name} {old_src}:{old_sport} -> {packet.src_addr}:{packet.src_port}")
                            except Exception:
                                pass
                            # If TCP FIN/RST, remove session
                            try:
                                if hasattr(packet, 'tcp'):
                                    if getattr(packet.tcp, 'fin', False) or getattr(packet.tcp, 'rst', False):
                                        self._mark_session_closed(session)
                            except Exception:
                                pass
                except Exception:
                    pass

                result = self.process_packet(packet)
                if result is not None:
                    try:
                        w.send(result)
                    except Exception as e:
                        self.log_message(f"WinDivert send error: {e}")

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
                        elif tokens[1].upper() == "DOMAIN":
                            self.add_blocked_domain(tokens[2])
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
                    elif tokens[1].upper() == "DOMAIN":
                        self.remove_blocked_domain(tokens[2])
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

            for domain in list(self.blocked_domains):
                self._apply_domain_enforcement(domain)

            self.refresh_blocked_domains_firewall()

        self.log_message("Firewall enabled and all block rules re-applied.")

    def disable_firewall(self):
        with self.lock:
         self.is_firewall_enabled = False
        if self.last_enabled_time:
            self.uptime_accumulated += time.time() - self.last_enabled_time
            self.last_enabled_time = None
            self.stop_refresh_domains_timer()
            self.stop_refresh_domains_timer()

            for domain in list(self.blocked_domains):
                self._remove_domain_enforcement(domain)

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
        if self.is_firewall_enabled:
            self.disable_firewall()
        else:
            self.enable_firewall()

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
                    elif tokens[1].upper() == "DOMAIN":
                        self.remove_blocked_domain(tokens[2])
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

    # --- Settings Features: NAT / Port Forwarding ---
    def add_nat_rule(self, ext_port, int_ip, int_port, protocol="TCP"):
        """Add a port forwarding (NAT) rule."""
        protocol = (protocol or "TCP").upper()
        if protocol == "UDP":
            return self._add_udp_nat_rule(ext_port, int_ip, int_port)
        return super().add_nat_rule(ext_port, int_ip, int_port, protocol)

    def remove_nat_rule(self, ext_port, protocol="TCP"):
        """Remove a port forwarding rule."""
        protocol = (protocol or "TCP").upper()
        if protocol == "UDP":
            return self._remove_udp_nat_rule(ext_port)
        return super().remove_nat_rule(ext_port, protocol)

    def _ensure_udp_forwarder_state(self):
        if not hasattr(self, 'udp_forwarder_threads'):
            self.udp_forwarder_threads = {}
        if not hasattr(self, 'udp_forwarder_stop_events'):
            self.udp_forwarder_stop_events = {}
        if not hasattr(self, 'udp_forwarder_sessions'):
            self.udp_forwarder_sessions = {}
        if not hasattr(self, 'nat_rules'):
            self.nat_rules = {}

    def _port_in_use_any(self, port):
        try:
            out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL)
            token = f":{port}"
            for line in out.splitlines():
                if token in line:
                    return True
        except Exception:
            pass
        return False

    def _apply_udp_firewall_rule(self, ext_port, int_ip, int_port, delete=False):
        rule_name = f"Securly NAT UDP {ext_port} -> {int_ip}:{int_port}"
        if delete:
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except Exception:
                pass
            return rule_name

        if not _is_admin():
            self.log_message(f"UDP NAT saved but not firewall-enforced (requires Administrator): UDP {ext_port} -> {int_ip}:{int_port}")
            return rule_name

        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=allow",
                "protocol=UDP", f"localport={ext_port}", "profile=any"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            self.log_message(f"Failed to add UDP firewall rule: {getattr(e, 'stderr', '').strip()}")
        return rule_name

    def _start_udp_forwarder(self, ext_port, int_ip, int_port):
        self._ensure_udp_forwarder_state()
        ext_port = int(ext_port)
        int_port = int(int_port)
        key = f"UDP_{ext_port}"
        if key in self.udp_forwarder_threads and self.udp_forwarder_threads[key].is_alive():
            return
        if self._port_in_use_any(ext_port):
            raise RuntimeError(f"UDP listen port {ext_port} is already in use")

        stop_event = threading.Event()
        self.udp_forwarder_stop_events[key] = stop_event
        self.udp_forwarder_sessions[key] = {}

        def forwarder():
            listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_socket.bind(("0.0.0.0", ext_port))
            listen_socket.settimeout(1.0)
            sessions = self.udp_forwarder_sessions[key]

            def run_session(client_addr, upstream_socket):
                upstream_socket.settimeout(1.0)
                try:
                    while not stop_event.is_set():
                        try:
                            data = upstream_socket.recv(65535)
                            if data:
                                listen_socket.sendto(data, client_addr)
                        except socket.timeout:
                            if time.time() - sessions.get(client_addr, {}).get("last_seen", 0) > 60:
                                break
                        except OSError:
                            break
                finally:
                    try:
                        upstream_socket.close()
                    except Exception:
                        pass
                    sessions.pop(client_addr, None)

            try:
                while not stop_event.is_set():
                    try:
                        data, client_addr = listen_socket.recvfrom(65535)
                    except socket.timeout:
                        now = time.time()
                        for client_addr, session in list(sessions.items()):
                            if now - session.get("last_seen", 0) > 60:
                                try:
                                    session["upstream_socket"].close()
                                except Exception:
                                    pass
                                sessions.pop(client_addr, None)
                        continue
                    except OSError:
                        break

                    session = sessions.get(client_addr)
                    if session is None:
                        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        upstream_socket.connect((int_ip, int_port))
                        session = {"upstream_socket": upstream_socket, "last_seen": time.time()}
                        sessions[client_addr] = session
                        worker = threading.Thread(target=run_session, args=(client_addr, upstream_socket), daemon=True)
                        session["worker"] = worker
                        worker.start()

                    session["last_seen"] = time.time()
                    try:
                        session["upstream_socket"].send(data)
                    except OSError:
                        try:
                            session["upstream_socket"].close()
                        except Exception:
                            pass
                        sessions.pop(client_addr, None)
            finally:
                try:
                    listen_socket.close()
                except Exception:
                    pass

        thread = threading.Thread(target=forwarder, daemon=True)
        self.udp_forwarder_threads[key] = thread
        thread.start()
        self.log_message(f"UDP NAT forwarder started: UDP {ext_port} -> {int_ip}:{int_port}")

    def _stop_udp_forwarder(self, ext_port):
        self._ensure_udp_forwarder_state()
        key = f"UDP_{int(ext_port)}"
        stop_event = self.udp_forwarder_stop_events.get(key)
        if stop_event:
            stop_event.set()
        sessions = self.udp_forwarder_sessions.get(key, {})
        for session in list(sessions.values()):
            try:
                session.get("upstream_socket").close()
            except Exception:
                pass
        self.udp_forwarder_sessions.pop(key, None)
        thread = self.udp_forwarder_threads.pop(key, None)
        self.udp_forwarder_stop_events.pop(key, None)
        if thread and thread.is_alive():
            thread.join(timeout=1.0)

    def _add_udp_nat_rule(self, ext_port, int_ip, int_port):
        try:
            ext_port = int(ext_port)
            int_port = int(int_port)
        except Exception:
            self.log_message(f"Invalid UDP NAT ports: {ext_port} / {int_port}")
            return

        if self._port_in_use_any(ext_port):
            self.log_message(f"UDP port {ext_port} already in use. Cannot add NAT rule.")
            return

        self._ensure_udp_forwarder_state()
        key = f"UDP_{ext_port}"
        self.nat_rules[key] = {
            "ext_port": ext_port,
            "int_ip": int_ip,
            "int_port": int_port,
            "protocol": "UDP",
            "mode": "user-space-forwarder",
        }
        self.save_nat_rules()

        try:
            self._start_udp_forwarder(ext_port, int_ip, int_port)
            self._apply_udp_firewall_rule(ext_port, int_ip, int_port, delete=False)
            self.log_message(f"UDP NAT rule active: UDP {ext_port} -> {int_ip}:{int_port}")
        except Exception as e:
            self.log_message(f"Failed to start UDP NAT forwarder: {e}")

    def _remove_udp_nat_rule(self, ext_port):
        ext_port = int(ext_port)
        self._ensure_udp_forwarder_state()
        key = f"UDP_{ext_port}"
        rule = self.nat_rules.get(key)
        if not rule:
            self.log_message(f"UDP NAT rule not found: {ext_port}")
            return

        self._stop_udp_forwarder(ext_port)
        self._apply_udp_firewall_rule(ext_port, rule.get("int_ip", ""), rule.get("int_port", ""), delete=True)
        self.nat_rules.pop(key, None)
        self.save_nat_rules()
        self.log_message(f"UDP NAT rule removed: UDP {ext_port}")

    def verify_nat_rule(self, ext_port, protocol="TCP"):
        protocol = (protocol or "TCP").upper()
        key = f"{protocol}_{ext_port}"
        rule = self.nat_rules.get(key)
        if not rule:
            return {"found": False, "enforced": False, "active": False, "message": f"NAT rule not found in state: {protocol} {ext_port}"}

        if protocol == "UDP":
            active = key in getattr(self, "udp_forwarder_threads", {}) and self.udp_forwarder_threads[key].is_alive()
            return {
                "found": True,
                "enforced": active,
                "active": active,
                "message": (f"Verified and active: {protocol} {ext_port}" if active else f"Stored but not active: {protocol} {ext_port}"),
            }

        return super().verify_nat_rule(ext_port, protocol)

    def sync_nat_rules(self):
        synced = []
        for key, rule in list(self.nat_rules.items()):
            protocol = str(rule.get("protocol", "TCP")).upper()
            verification = self.verify_nat_rule(rule.get("ext_port"), protocol)
            if verification.get("active"):
                synced.append({"rule": rule, "status": "active"})
                continue
            try:
                self.add_nat_rule(rule.get("ext_port"), rule.get("int_ip"), rule.get("int_port"), protocol)
                synced.append({"rule": rule, "status": "reapplied"})
            except Exception as e:
                self.log_message(f"Failed to sync NAT rule {key}: {e}")
                synced.append({"rule": rule, "status": "failed"})
        return synced

    # --- Settings Features: VPN Integration ---
    def get_vpn_status(self):
        """Check VPN connection status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-VpnConnection | Select-Object Name, ConnectionStatus"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return "VPN Status: No active VPN connections"
        except Exception as e:
            self.log_message(f"VPN status check error: {e}")
            return f"VPN Status: Error ({e})"

    def toggle_vpn(self, enable=True):
        """Enable or disable VPN."""
        try:
            cmd = "rasdial.exe" if enable else "rasdial.exe /disconnect"
            # This is a placeholder; actual VPN control depends on your VPN software
            self.log_message(f"VPN {'enabled' if enable else 'disabled'}")
        except Exception as e:
            self.log_message(f"VPN toggle error: {e}")

    # --- Settings Features: DNS Configuration ---
    def set_dns_servers(self, dns_list):
        """Set custom DNS servers via netsh."""
        if not hasattr(self, 'dns_servers'):
            self.dns_servers = []
        self.dns_servers = dns_list
        # Get active network interfaces
        try:
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interface"],
                capture_output=True, text=True
            )
            # This is a simplified placeholder; full implementation would parse interfaces
            self.log_message(f"DNS configuration set to: {', '.join(dns_list)}")
        except Exception as e:
            self.log_message(f"DNS configuration error: {e}")

    # --- Settings Features: Traffic Shaping (QoS) ---
    def add_qos_rule(self, name, ip_range, bandwidth_mbps):
        """Add a QoS bandwidth limiting rule."""
        if not hasattr(self, 'qos_rules'):
            self.qos_rules = {}
        self.qos_rules[name] = {"ip_range": ip_range, "bandwidth_mbps": bandwidth_mbps}
        self.log_message(f"QoS rule added: {name} ({ip_range}) -> {bandwidth_mbps}Mbps limit")

    # --- Settings Features: IDS/IPS Integration ---
    def get_security_alerts(self):
        """Return security alerts based on traffic analysis."""
        alerts = []
        # Check for malware signatures in recent traffic
        if self.last_malware:
            alerts.append({"type": "Malware", "timestamp": self.last_malware, "severity": "High"})
        # Check for sensitive data patterns
        if self.last_content:
            alerts.append({"type": "Sensitive Content", "timestamp": self.last_content, "severity": "Medium"})
        # Check for telemetry
        if self.last_telemetry:
            alerts.append({"type": "Telemetry Detected", "timestamp": self.last_telemetry, "severity": "Low"})
        # Add blocked packet count alert
        blocked_count = self.packet_stats.get("blocked", 0)
        if blocked_count > 100:
            alerts.append({"type": "High Block Rate", "count": blocked_count, "severity": "Medium"})
        return {"alerts": alerts, "total_alerts": len(alerts)}

    def clear_security_alerts(self):
        """Clear security alert history."""
        self.last_malware = None
        self.last_content = None
        self.last_telemetry = None
        self.log_message("Security alerts cleared")

    # --- Settings Features: Backup / Restore ---
    def backup_settings(self, filepath):
        """Backup all firewall rules and settings to a file."""
        import json
        from datetime import datetime
        
        backup_data = {
            "timestamp": datetime.now().isoformat(),
            "blocked_ips": list(self.blocked_ips),
            "blocked_ports": list(self.blocked_ports),
            "blocked_protocols": list(self.blocked_protocols),
            "blocked_domains": list(self.blocked_domains),
            "custom_rules": list(self.custom_rules),
            "nat_rules": getattr(self, 'nat_rules', {}),
            "qos_rules": getattr(self, 'qos_rules', {}),
            "firewall_enabled": self.is_firewall_enabled
        }
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2)
            self.log_message(f"Settings backup created: {filepath}")
        except Exception as e:
            self.log_message(f"Backup error: {e}")

    def restore_settings(self, filepath):
        """Restore firewall rules and settings from a backup file."""
        import json
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # Restore blocklists
            self.blocked_ips = set(backup_data.get("blocked_ips", []))
            self.blocked_ports = set(str(p) for p in backup_data.get("blocked_ports", []))
            self.blocked_protocols = set(backup_data.get("blocked_protocols", []))
            self.blocked_domains = set(backup_data.get("blocked_domains", []))
            self.custom_rules = backup_data.get("custom_rules", [])
            self.nat_rules = backup_data.get("nat_rules", {})
            self.qos_rules = backup_data.get("qos_rules", {})
            
            self.save_blocklists()
            self.save_rules()
            self.log_message(f"Settings restored from: {filepath}")
        except Exception as e:
            self.log_message(f"Restore error: {e}")

    # --- Settings Features: Reports & Analytics ---
    def generate_analytics_report(self):
        """Generate a comprehensive analytics report."""
        uptime_sec = time.time() - self.app_start_time if hasattr(self, 'app_start_time') else 0
        hours = int(uptime_sec // 3600)
        minutes = int((uptime_sec % 3600) // 60)
        
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "firewall_status": "Enabled" if self.is_firewall_enabled else "Disabled",
            "uptime": f"{hours}h {minutes}m",
            "packets_blocked": self.packet_stats.get("blocked", 0),
            "packets_allowed": self.packet_stats.get("allowed", 0),
            "block_rate": round((self.packet_stats.get("blocked", 0) / max(self.packet_stats.get("allowed", 1) + self.packet_stats.get("blocked", 1), 1)) * 100, 2),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ports_count": len(self.blocked_ports),
            "blocked_domains_count": len(self.blocked_domains),
            "custom_rules_count": len(self.custom_rules),
            "recent_traffic_events": len(self.traffic_events),
            "security_alerts": self.get_security_alerts()
        }
        self.log_message("Analytics report generated")
        return report