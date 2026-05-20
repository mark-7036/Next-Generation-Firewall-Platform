Securly Next-Generation-Firewall-Platform

A powerful PyQt5-based firewall application for Windows that provides real-time packet monitoring, IP/port blocking, domain filtering, and comprehensive security logging.

## Features

✅ **Dashboard**
- Real-time firewall status and packet statistics
- Enable/disable firewall with one click
- Uptime tracking and performance metrics
- Security event summaries

✅ **Rules Management**
- Block/unblock IPs, ports, and protocols
- Custom rule creation and deletion
- Persistent rule storage (JSON & text formats)
- Quick rule import/export

✅ **Advanced Filtering**
- IP-based blocking (single IPs or ranges)
- Port blocking (TCP/UDP)
- Protocol filtering (TCP, UDP, ICMP)
- Domain-level blocking (via hosts file + firewall rules)
- DPI (Deep Packet Inspection) pattern matching
- Telemetry blocking (Microsoft services by default)

✅ **Logging & Monitoring**
- Real-time security logs
- Three persistent log files:
  - `firewall_gui.log` — User actions & rule changes
  - `firewall_history_full.log` — Complete action history
  - `firewall_traffic.log` — Python logging (with timestamps)
- Export logs to file
- Clear logs with confirmation

✅ **Windows Integration**
- Native Windows Firewall rule creation via `netsh advfirewall`
- Admin-level access for rule management
- System startup compatibility

✅ **Settings (Expandable)**
- NAT / Port Forwarding (stub)
- VPN Integration (stub)
- DNS Configuration (stub)
- Traffic Shaping / QoS (stub)
- IDS/IPS Integration (stub)
- Backup / Restore (stub)
- Reports & Analytics (stub)

## Installation

### Requirements
- **OS:** Windows 7 or later
- **Python:** 3.9+
- **Admin Rights:** Required for Windows Firewall rule management

### Steps

1. **Clone or download the repository:**
   ```bash
   git clone https://github.com/mark-7036/Securly-NGFW-Platform.git
   cd firewall-windows
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

   **Important:** Run as Administrator for firewall rules to take effect.

## Usage Guide

### Starting the GUI

```bash
python main.py
```

The application opens with four tabs:

#### 1. 📊 Dashboard
- View firewall status (Enabled / Disabled)
- See real-time packet counts (Blocked / Allowed)
- Check uptime and response time
- Toggle firewall on/off

#### 2. 📋 Rules Management
Create custom blocking rules in these formats:

```
BLOCK IP <IP_ADDRESS>          # Block a single IP
BLOCK PORT <PORT_NUMBER>       # Block a port (TCP/UDP)
BLOCK PROTOCOL <PROTOCOL>      # Block a protocol (TCP, UDP, ICMP)
BLOCK DOMAIN <DOMAIN_NAME>     # Block a domain
```

**Examples:**
```
BLOCK IP 192.168.1.100
BLOCK PORT 8080
BLOCK PROTOCOL ICMP
BLOCK DOMAIN example.com
```

- Enter a rule in the input field and click **➕ Add Rule**
- Select a rule and click **➖ Remove** to delete it
- Click **🗑️ Clear All** to remove all rules at once

#### 3. 📜 Logs
- View the last 100 log entries
- Click **🔄 Refresh** to reload logs from disk
- Click **📥 Export** to save logs to a file
- Click **🗑️ Clear Logs** to erase all entries

#### 4. ⚙️ Settings (Preview)
Buttons for upcoming features:
- NAT / Port Forwarding
- VPN Integration
- DNS Configuration
- Traffic Shaping (QoS)
- IDS/IPS Integration
- Backup / Restore
- Reports & Analytics

(Currently show placeholder messages; full implementation coming soon)

## Configuration Files

The application stores all data in the working directory:

```
d:\Firewall\
├── blocklists.json           # IPs, ports, protocols, domains
├── rules.txt                 # Custom rules (one per line)
├── firewall_status.json      # Current firewall state (enabled/disabled)
├── firewall_uptime.json      # Uptime tracking
├── firewall_history.json     # Status change history
├── firewall_gui.log          # GUI action log
├── firewall_traffic.log      # Python logging output
└── firewall_history_full.log # Complete persistent log
```

### blocklists.json Format
```json
{
  "blocked_ips": ["192.168.1.100", "8.8.8.8"],
  "blocked_ports": ["8080", "443"],
  "blocked_protocols": ["ICMP"],
  "dpi_patterns": [],
  "custom_blocklist": [],
  "blocked_domains": ["example.com"]
}
```

### rules.txt Format
```
BLOCK IP 192.168.1.100
BLOCK PORT 8080
BLOCK PROTOCOL TCP
BLOCK DOMAIN example.com
```

## Architecture

### Core Components

**firewall.py** — Main engine
- `FirewallApp` class handles all blocking logic
- Windows Firewall rule creation via `netsh advfirewall`
- Packet sniffing (Scapy) & traffic monitoring
- Persistent storage (JSON/text)
- Comprehensive logging

**firewall_controller.py** — UI bridge
- Wraps `FirewallApp` for the GUI
- Exposes methods for dashboard, rules, logs, and settings
- Provides thread-safe access to firewall state

**main_window.py** — PyQt5 GUI
- Four-tab interface (Dashboard, Rules, Logs, Settings)
- Real-time refresh with `QTimer` (every 2 seconds)
- Dark theme stylesheet for readability
- Event handlers for all user actions

**main.py** — Entrypoint
- Initializes `QApplication` and `MainWindow`
- Launches the GUI

## Common Tasks

### Block an IP Address
1. Go to **📋 Rules** tab
2. Enter: `BLOCK IP 192.168.1.100`
3. Click **➕ Add Rule**
4. See log entry in **📜 Logs** tab

### Unblock a Port
1. Go to **📋 Rules** tab
2. Select the rule (e.g., `BLOCK PORT 8080`)
3. Click **➖ Remove**
4. Port is immediately unblocked

### Export Logs for Analysis
1. Go to **📜 Logs** tab
2. Click **📥 Export**
3. Logs are saved to `firewall_logs_export.txt`

### Disable Firewall Temporarily
1. Go to **📊 Dashboard** tab
2. Click **🟢 Enable Firewall** (or **🔴 Disable Firewall**)
3. All blocking rules are suspended/reapplied

## Troubleshooting

### "Log is not working"
- Ensure the app is run from `d:\Firewall\` directory, or modify file paths in `firewall.py`
- Check file permissions — `firewall_gui.log` must be writable
- Look for entries in **📜 Logs** tab (refreshes every 2 seconds)

### "Port blocking doesn't work"
- **Run as Administrator** — Windows Firewall rules require admin privileges
- Check Windows Event Viewer for firewall rule errors
- Verify rule created: `netsh advfirewall firewall show rule name=all`

### "Unblocked port still stays blocked"
- Admin privileges may be required for rule deletion
- Fallback cleanup logic now attempts criteria-based deletion after name-based delete fails

### Application crashes on startup
- Verify Python 3.9+ is installed
- Check all dependencies: `pip install -r requirements.txt`
- Run with `python -c "from firewall import FirewallApp; print('OK')"` to debug imports

## Development

### Adding a New Feature

1. **Add logic to `FirewallApp`** (firewall.py)
   ```python
   def new_feature(self):
       self.log_message("New feature activated")
       # Implementation here
   ```

2. **Add method to `FirewallController`** (firewall_controller.py)
   ```python
   def new_feature(self):
       return self.firewall.new_feature()
   ```

3. **Add UI in `main_window.py`**
   ```python
   def show_new_feature(self):
       result = self.controller.new_feature()
       QMessageBox.information(self, "Feature", result)
   ```

### Running Tests
```bash
python -c "from firewall import FirewallApp; fw=FirewallApp(); fw.log_message('TEST'); print('OK')"
```

## Logging

All actions are logged to three files (created automatically):

1. **firewall_gui.log** — User-facing actions
   ```
   [17:25:12] TEST LOG ENTRY FROM DEBUG
   [17:26:23] All custom rules cleared.
   ```

2. **firewall_traffic.log** — Python logging (with timestamps)
   ```
   2026-05-19 17:25:12,461 - INFO - TEST LOG ENTRY FROM DEBUG
   ```

3. **firewall_history_full.log** — Complete persistent history
   ```
   [17:25:12] TEST LOG ENTRY FROM DEBUG
   ```

## Performance

- Dashboard refresh: ~200ms (every 2 seconds)
- Rule addition/removal: ~100-500ms (depends on netsh)
- Log scrolling: No lag (capped at 200 traffic events in memory)
- Memory usage: ~50-100 MB (typical)

## Security Notes

⚠️ **Windows Admin Required**
- Firewall rule management requires elevated privileges
- Always run as Administrator for rules to take effect

⚠️ **Network Access**
- Packet sniffing may require admin + specific NIC permissions
- Use `pydivert` for advanced filtering (optional, requires WinDivert driver)

⚠️ **Persistent Rules**
- Rules are applied directly to Windows Firewall
- Disabling the app does NOT remove rules unless you explicitly disable the firewall first

## Future Roadmap

- [ ] IP range blocking (CIDR notation)
- [ ] Advanced DPI pattern editor
- [ ] Traffic visualization (charts/graphs)
- [ ] VPN integration
- [ ] DNS over HTTPS (DoH) proxy
- [ ] Multi-language support
- [ ] System tray mode

## Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m "Add your feature"`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

Proprietary License — see LICENSE file for details

## Support

For issues, questions, or feature requests:
- Open a GitHub Issue
- Check existing issues/docs first
- Include Windows version, Python version, and error logs

---

⚠️ Please Keep In Mind, This Product Is Still Under Development!!

**Happy firewalling! 🔥**

*Securly— Secure your network, one rule at a time.*
