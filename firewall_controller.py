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

    def get_packet_engine(self):
        return self.firewall.get_packet_engine()

    def get_packet_engine_options(self):
        return self.firewall.get_packet_engine_options()

    def get_packet_engine_status(self):
        return self.firewall.get_packet_engine_status()

    def set_packet_engine(self, engine):
        try:
            self.firewall.set_packet_engine(engine)
            return self.firewall.get_packet_engine_status()
        except Exception as e:
            return {"error": str(e)}

    def get_recent_log(self, n=10):
        return self.firewall.get_recent_log(n)

    def enable_firewall(self):
        self.firewall.enable_firewall()

    def disable_firewall(self):
        self.firewall.disable_firewall()

    def toggle_firewall(self):
        if getattr(self.firewall, 'is_firewall_enabled', False):
            self.firewall.disable_firewall()
        else:
            self.firewall.enable_firewall()

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

    # --- Settings: NAT / Port Forwarding ---
    def get_nat_rules(self):
        """Retrieve port forwarding rules."""
        return getattr(self.firewall, 'nat_rules', {})

    def verify_nat_rule(self, ext_port, protocol="TCP"):
        """Verify NAT/port forwarding state against the OS."""
        try:
            return self.firewall.verify_nat_rule(ext_port, protocol)
        except Exception as e:
            return {"found": False, "enforced": False, "active": False, "message": f"Error: {e}"}

    def sync_nat_rules(self):
        """Re-apply stored NAT rules if OS state drifted."""
        try:
            return self.firewall.sync_nat_rules()
        except Exception as e:
            return [{"status": "error", "error": str(e)}]

    def add_nat_rule(self, ext_port, int_ip, int_port, protocol="TCP"):
        """Add a NAT/port forwarding rule."""
        try:
            self.firewall.add_nat_rule(ext_port, int_ip, int_port, protocol)
            verification = self.verify_nat_rule(ext_port, protocol)
            if verification.get("active"):
                return f"NAT rule added and verified: {protocol} {ext_port} -> {int_ip}:{int_port}"
            if verification.get("enforced"):
                return f"NAT rule added and partially verified: {protocol} {ext_port} -> {int_ip}:{int_port}"
            return f"NAT rule stored: {protocol} {ext_port} -> {int_ip}:{int_port}"
        except Exception as e:
            return f"Error: {e}"

    def remove_nat_rule(self, ext_port, protocol="TCP"):
        """Remove a NAT/port forwarding rule."""
        try:
            self.firewall.remove_nat_rule(ext_port, protocol)
            return f"NAT rule removed: {protocol} {ext_port}"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: VPN Integration ---
    def get_vpn_status(self):
        """Check VPN connection status."""
        try:
            return self.firewall.get_vpn_status()
        except Exception as e:
            return f"VPN Status: Disconnected ({e})"

    def toggle_vpn(self, enable=True):
        """Toggle VPN on/off."""
        try:
            self.firewall.toggle_vpn(enable)
            return f"VPN {'enabled' if enable else 'disabled'}"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: DNS Configuration ---
    def get_dns_config(self):
        """Get current DNS configuration."""
        return getattr(self.firewall, 'dns_servers', ["8.8.8.8", "8.8.4.4"])

    def set_dns_servers(self, dns_list):
        """Set custom DNS servers."""
        try:
            self.firewall.set_dns_servers(dns_list)
            return f"DNS set to: {', '.join(dns_list)}"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: Traffic Shaping (QoS) ---
    def get_qos_rules(self):
        """Get traffic shaping rules."""
        return getattr(self.firewall, 'qos_rules', {})

    def add_qos_rule(self, name, ip_range, bandwidth_mbps):
        """Add a QoS bandwidth limit rule."""
        try:
            self.firewall.add_qos_rule(name, ip_range, bandwidth_mbps)
            return f"QoS rule added: {name} ({ip_range}) -> {bandwidth_mbps}Mbps"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: IDS/IPS Integration ---
    def get_security_alerts(self):
        """Get IDS/IPS alerts and suspicious activity."""
        try:
            return self.firewall.get_security_alerts()
        except Exception as e:
            return {"alerts": [], "error": str(e)}

    def clear_security_alerts(self):
        """Clear all security alerts."""
        try:
            self.firewall.clear_security_alerts()
            return "Security alerts cleared"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: Backup / Restore ---
    def backup_settings(self, filepath):
        """Backup all firewall rules and settings."""
        try:
            self.firewall.backup_settings(filepath)
            return f"Backup created: {filepath}"
        except Exception as e:
            return f"Error: {e}"

    def restore_settings(self, filepath):
        """Restore firewall rules and settings from backup."""
        try:
            self.firewall.restore_settings(filepath)
            return f"Backup restored: {filepath}"
        except Exception as e:
            return f"Error: {e}"

    # --- Settings: Reports & Analytics ---
    def get_analytics(self):
        """Generate analytics report."""
        try:
            return self.firewall.generate_analytics_report()
        except Exception as e:
            return {"error": str(e)}

    # --- Settings: Domain Blocking ---
    def get_blocked_domains(self):
        """Retrieve list of blocked domains."""
        return list(getattr(self.firewall, 'blocked_domains', []))

    def add_blocked_domain(self, domain):
        """Add domain to block list with OS-level enforcement."""
        try:
            self.firewall.add_blocked_domain(domain)
            return f"Domain blocked: {domain}"
        except Exception as e:
            return f"Error: {e}"

    def remove_blocked_domain(self, domain):
        """Remove domain from block list."""
        try:
            self.firewall.remove_blocked_domain(domain)
            return f"Domain unblocked: {domain}"
        except Exception as e:
            return f"Error: {e}"

    def is_admin(self):
        """Check if running with Administrator rights."""
        from firewall import _is_admin
        return _is_admin()
