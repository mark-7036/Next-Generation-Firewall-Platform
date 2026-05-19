import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from firewall import FirewallApp

class FirewallController:
    def __init__(self):
        self.firewall = FirewallApp()

    def get_status(self):
        return self.firewall.get_status()

    def get_stats(self):
        return self.firewall.get_stats()

    def get_recent_log(self, n=10):
        return self.firewall.get_recent_log(n)

    def enable_firewall(self):
        self.firewall.enable_firewall()

    def disable_firewall(self):
        self.firewall.disable_firewall()

    def toggle_firewall(self):
        self.firewall.toggle_firewall()

    def get_rules(self):
        return list(self.firewall.custom_rules)

    def add_rule(self, rule):
        self.firewall.add_custom_rule(rule)

    def remove_rule(self, idx):
        self.firewall.remove_custom_rule(idx)

    def clear_logs(self):
        self.firewall.clear_logs()

    def clear_rules(self):
        self.firewall.clear_custom_rules()

    # --- Settings feature stubs ---
    def nat_port_forwarding(self):
        try:
            self.firewall.log_message("NAT / Port Forwarding requested")
        except Exception:
            pass
        return "NAT / Port Forwarding: not implemented yet"

    def vpn_integration(self):
        try:
            self.firewall.log_message("VPN Integration requested")
        except Exception:
            pass
        return "VPN Integration: not implemented yet"

    def dns_configuration(self):
        try:
            self.firewall.log_message("DNS Configuration requested")
        except Exception:
            pass
        return "DNS Configuration: not implemented yet"

    def traffic_shaping(self):
        try:
            self.firewall.log_message("Traffic Shaping (QoS) requested")
        except Exception:
            pass
        return "Traffic Shaping (QoS): not implemented yet"

    def ids_ips_integration(self):
        try:
            self.firewall.log_message("IDS/IPS Integration requested")
        except Exception:
            pass
        return "IDS/IPS Integration: not implemented yet"

    def backup_restore(self):
        try:
            self.firewall.log_message("Backup/Restore requested")
        except Exception:
            pass
        return "Backup / Restore: not implemented yet"

    def reports_analytics(self):
        try:
            self.firewall.log_message("Reports & Analytics requested")
        except Exception:
            pass
        return "Reports & Analytics: not implemented yet"
