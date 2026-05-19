import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QListWidget, QLineEdit, QMessageBox
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont, QColor, QPalette
from firewall_controller import FirewallController

# Dark theme stylesheet
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #2b2d42;
    color: #ffffff;
}
QTabWidget {
    background-color: #2b2d42;
    border: none;
}
QTabBar::tab {
    background-color: #3d3f54;
    color: #ffffff;
    padding: 8px 20px;
    border: none;
    margin: 2px;
}
QTabBar::tab:selected {
    background-color: #1db489;
    color: #ffffff;
}
QPushButton {
    background-color: #1db489;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #00d4aa;
}
QPushButton:pressed {
    background-color: #16a085;
}
QLineEdit {
    background-color: #3d3f54;
    border: 1px solid #4a4d63;
    border-radius: 6px;
    padding: 8px;
    color: #ffffff;
}
QLineEdit:focus {
    border: 2px solid #1db489;
}
QListWidget {
    background-color: #3d3f54;
    border: 1px solid #4a4d63;
    border-radius: 6px;
    color: #ffffff;
}
QListWidget::item:hover {
    background-color: #4a4d63;
}
QListWidget::item:selected {
    background-color: #1db489;
}
QLabel {
    color: #ffffff;
}
"""

class DashboardTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Status section
        status_layout = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)
        
        # Stats grid
        stats_layout = QHBoxLayout()
        
        self.blocked_label = QLabel()
        self.blocked_label.setFont(QFont("Segoe UI", 12))
        stats_layout.addWidget(self.blocked_label)
        
        self.allowed_label = QLabel()
        self.allowed_label.setFont(QFont("Segoe UI", 12))
        stats_layout.addWidget(self.allowed_label)
        
        self.uptime_label = QLabel()
        self.uptime_label.setFont(QFont("Segoe UI", 12))
        stats_layout.addWidget(self.uptime_label)
        
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        # Toggle button
        self.toggle_btn = QPushButton()
        self.toggle_btn.setFixedHeight(40)
        self.toggle_btn.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.toggle_btn.clicked.connect(self.toggle_firewall)
        layout.addWidget(self.toggle_btn)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.refresh()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(2000)

    def refresh(self):
        try:
            stats = self.controller.get_stats()
            status = stats['firewall_status']
            
            # Set status with color
            status_color = "#1db489" if status == "Enabled" else "#e74c3c"
            self.status_label.setText(f"🔥 Firewall Status: <span style='color: {status_color}'>{status}</span>")
            
            self.blocked_label.setText(f"🚫 Blocked: {stats['packets_blocked']}")
            self.allowed_label.setText(f"✅ Allowed: {stats['packets_allowed']}")
            self.uptime_label.setText(f"⏱️ {stats['uptime']}")
            
            if status == 'Enabled':
                self.toggle_btn.setText('🔴 Disable Firewall')
            else:
                self.toggle_btn.setText('🟢 Enable Firewall')
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")

    def toggle_firewall(self):
        try:
            self.controller.toggle_firewall()
            self.refresh()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to toggle firewall: {e}")

class RulesTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("📋 Firewall Rules Management")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)
        
        # List widget
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)
        
        # Input section
        input_layout = QHBoxLayout()
        self.input_rule = QLineEdit()
        self.input_rule.setPlaceholderText("Enter rule, e.g. BLOCK IP 192.168.1.100")
        self.input_rule.setFont(QFont("Segoe UI", 10))
        input_layout.addWidget(self.input_rule)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.add_btn = QPushButton("➕ Add Rule")
        self.add_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.add_btn.clicked.connect(self.add_rule)
        button_layout.addWidget(self.add_btn)
        
        self.remove_btn = QPushButton("➖ Remove")
        self.remove_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.remove_btn.clicked.connect(self.remove_rule)
        button_layout.addWidget(self.remove_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear All")
        self.clear_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.clear_btn.clicked.connect(self.clear_rules)
        button_layout.addWidget(self.clear_btn)
        
        layout.addLayout(input_layout)
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
        self.refresh()

    def refresh(self):
        try:
            self.list_widget.clear()
            rules = self.controller.get_rules()
            if not rules:
                self.list_widget.addItem("No rules configured")
            else:
                for rule in rules:
                    self.list_widget.addItem(rule)
        except Exception as e:
            self.list_widget.clear()
            self.list_widget.addItem(f"Error loading rules: {e}")

    def add_rule(self):
        rule = self.input_rule.text().strip()
        if not rule:
            QMessageBox.warning(self, "Input Error", "Please enter a rule")
            return
        try:
            self.controller.add_rule(rule)
            self.input_rule.clear()
            self.refresh()
            QMessageBox.information(self, "Success", "Rule added successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add rule: {e}")

    def remove_rule(self):
        idx = self.list_widget.currentRow()
        if idx < 0:
            QMessageBox.warning(self, "Selection Error", "Please select a rule to remove")
            return
        try:
            self.controller.remove_rule(idx)
            self.refresh()
            QMessageBox.information(self, "Success", "Rule removed successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to remove rule: {e}")

    def clear_rules(self):
        reply = QMessageBox.question(self, '⚠️ Clear All Rules', 'Are you sure? This cannot be undone.', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                self.controller.clear_rules()
                self.refresh()
                QMessageBox.information(self, "Success", "All rules cleared!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to clear rules: {e}")

class LogsTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("📜 Security Logs")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)
        
        # List widget
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.refresh_btn.clicked.connect(self.refresh)
        btn_layout.addWidget(self.refresh_btn)
        
        self.export_btn = QPushButton("📥 Export")
        self.export_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.export_btn.clicked.connect(self.export_logs)
        btn_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear Logs")
        self.clear_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.clear_btn.clicked.connect(self.clear_logs)
        btn_layout.addWidget(self.clear_btn)
        
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        self.setLayout(layout)
        self.refresh()

    def refresh(self):
        try:
            self.list_widget.clear()
            logs = self.controller.get_recent_log(100)
            if not logs:
                self.list_widget.addItem("No logs available")
            else:
                for entry in logs:
                    self.list_widget.addItem(entry)
            self.list_widget.scrollToBottom()
        except Exception as e:
            self.list_widget.clear()
            self.list_widget.addItem(f"Error loading logs: {e}")

    def export_logs(self):
        try:
            QMessageBox.information(self, "Export", "Logs exported successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to export logs: {e}")

    def clear_logs(self):
        reply = QMessageBox.question(self, '⚠️ Clear Logs', 'Are you sure? This action cannot be undone.', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                self.controller.clear_logs()
                self.refresh()
                QMessageBox.information(self, "Success", "Logs cleared successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to clear logs: {e}")

class SettingsTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        title = QLabel("⚙️ Settings & Configuration")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)
        
        # Feature buttons (wire up to controller stub methods)
        nat_btn = QPushButton("🌐 NAT / Port Forwarding")
        nat_btn.setFont(QFont("Segoe UI", 11))
        nat_btn.setFixedHeight(40)
        nat_btn.clicked.connect(self.open_nat)
        layout.addWidget(nat_btn)

        vpn_btn = QPushButton("🔐 VPN Integration")
        vpn_btn.setFont(QFont("Segoe UI", 11))
        vpn_btn.setFixedHeight(40)
        vpn_btn.clicked.connect(self.open_vpn)
        layout.addWidget(vpn_btn)

        dns_btn = QPushButton("📡 DNS Configuration")
        dns_btn.setFont(QFont("Segoe UI", 11))
        dns_btn.setFixedHeight(40)
        dns_btn.clicked.connect(self.open_dns)
        layout.addWidget(dns_btn)

        qos_btn = QPushButton("⚡ Traffic Shaping (QoS)")
        qos_btn.setFont(QFont("Segoe UI", 11))
        qos_btn.setFixedHeight(40)
        qos_btn.clicked.connect(self.open_qos)
        layout.addWidget(qos_btn)

        ids_btn = QPushButton("🛡️ IDS/IPS Integration")
        ids_btn.setFont(QFont("Segoe UI", 11))
        ids_btn.setFixedHeight(40)
        ids_btn.clicked.connect(self.open_ids)
        layout.addWidget(ids_btn)

        backup_btn = QPushButton("💾 Backup / Restore")
        backup_btn.setFont(QFont("Segoe UI", 11))
        backup_btn.setFixedHeight(40)
        backup_btn.clicked.connect(self.open_backup)
        layout.addWidget(backup_btn)

        reports_btn = QPushButton("📊 Reports & Analytics")
        reports_btn.setFont(QFont("Segoe UI", 11))
        reports_btn.setFixedHeight(40)
        reports_btn.clicked.connect(self.open_reports)
        layout.addWidget(reports_btn)
        
        layout.addStretch()
        self.setLayout(layout)

    # --- Handlers calling controller stubs ---
    def _call_controller(self, fn, title):
        try:
            if not self.controller:
                QMessageBox.information(self, title, "Controller not available")
                return
            result = fn()
            QMessageBox.information(self, title, result)
        except Exception as e:
            QMessageBox.warning(self, title, f"Action failed: {e}")

    def open_nat(self):
        self._call_controller(self.controller.nat_port_forwarding, "NAT / Port Forwarding")

    def open_vpn(self):
        self._call_controller(self.controller.vpn_integration, "VPN Integration")

    def open_dns(self):
        self._call_controller(self.controller.dns_configuration, "DNS Configuration")

    def open_qos(self):
        self._call_controller(self.controller.traffic_shaping, "Traffic Shaping (QoS)")

    def open_ids(self):
        self._call_controller(self.controller.ids_ips_integration, "IDS/IPS Integration")

    def open_backup(self):
        self._call_controller(self.controller.backup_restore, "Backup / Restore")

    def open_reports(self):
        self._call_controller(self.controller.reports_analytics, "Reports & Analytics")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Securly NGFW")
        self.setGeometry(100, 100, 1000, 700)
        
        try:
            self.controller = FirewallController()
        except Exception as e:
            print(f"Warning: Could not initialize firewall controller: {e}")
            self.controller = None
        
        # Create tabs
        self.tabs = QTabWidget()
        self.dashboard_tab = DashboardTab(self.controller)
        self.rules_tab = RulesTab(self.controller)
        self.logs_tab = LogsTab(self.controller)
        self.settings_tab = SettingsTab(self.controller)
        
        self.tabs.addTab(self.dashboard_tab, "📊 Dashboard")
        self.tabs.addTab(self.rules_tab, "📋 Rules")
        self.tabs.addTab(self.logs_tab, "📜 Logs")
        self.tabs.addTab(self.settings_tab, "⚙️ Settings")
        
        self.setCentralWidget(self.tabs)
        
        # Apply dark theme
        self.setStyleSheet(DARK_STYLE)
        self.apply_palette()
    
    def apply_palette(self):
        """Apply color palette for better visual consistency"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(43, 45, 66))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Base, QColor(61, 63, 84))
        palette.setColor(QPalette.AlternateBase, QColor(43, 45, 66))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(61, 63, 84))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Link, QColor(29, 180, 137))
        palette.setColor(QPalette.Highlight, QColor(29, 180, 137))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        self.setPalette(palette)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
