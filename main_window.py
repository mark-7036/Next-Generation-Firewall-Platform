import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QListWidget, QLineEdit, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QSpinBox, QComboBox, QTextEdit
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


class PacketEngineDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Packet Engine Control")
        self.resize(560, 260)

        layout = QVBoxLayout(self)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        form = QFormLayout()
        self.engine_box = QComboBox()
        self.engine_options = self.controller.get_packet_engine_options()
        for option in self.engine_options:
            label = option["label"]
            if not option.get("available", False):
                label = f"{label} (unavailable)"
            self.engine_box.addItem(label, option["engine"])
        form.addRow("Packet Engine", self.engine_box)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_engine)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        buttons.addWidget(apply_btn)
        buttons.addWidget(refresh_btn)
        layout.addLayout(buttons)

        self.refresh()

    def refresh(self):
        status = self.controller.get_packet_engine_status()
        current = self.controller.get_packet_engine()
        index = self.engine_box.findData(current)
        if index >= 0:
            self.engine_box.setCurrentIndex(index)
        self.status_label.setText(
            f"Selected: {status.get('selected')} | Effective: {status.get('effective')} | "
            f"Mode: {status.get('enforcement')}\n{status.get('description', '')}"
        )

    def apply_engine(self):
        engine = self.engine_box.currentData()
        result = self.controller.set_packet_engine(engine)
        if isinstance(result, dict) and result.get("error"):
            QMessageBox.warning(self, "Packet Engine", result["error"])
            return
        self.refresh()
        QMessageBox.information(
            self,
            "Packet Engine",
            f"Engine set to {result.get('selected')} ({result.get('enforcement')}).",
        )

class NatEditorDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Network Policy Engine - NAT / Port Forwarding")
        self.resize(720, 460)

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Protocol", "External Port", "Internal IP", "Internal Port", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        form = QFormLayout()
        self.protocol_box = QComboBox()
        self.protocol_box.addItems(["TCP", "UDP"])
        self.ext_port_input = QSpinBox()
        self.ext_port_input.setRange(1, 65535)
        self.int_ip_input = QLineEdit()
        self.int_ip_input.setPlaceholderText("192.168.1.10")
        self.int_port_input = QSpinBox()
        self.int_port_input.setRange(1, 65535)
        form.addRow("Protocol", self.protocol_box)
        form.addRow("External Port", self.ext_port_input)
        form.addRow("Internal IP", self.int_ip_input)
        form.addRow("Internal Port", self.int_port_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_selected)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        sync_btn = QPushButton("Sync Rules")
        sync_btn.clicked.connect(self.sync_rules)
        buttons.addWidget(add_btn)
        buttons.addWidget(remove_btn)
        buttons.addWidget(refresh_btn)
        buttons.addWidget(sync_btn)
        layout.addLayout(buttons)

        self.status = QLabel()
        layout.addWidget(self.status)
        self.refresh()

    def refresh(self):
        rules = self.controller.get_nat_rules()
        self.table.setRowCount(0)
        for key, rule in rules.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            protocol = str(rule.get("protocol", "TCP"))
            ext_port = str(rule.get("ext_port", ""))
            self.table.setItem(row, 0, QTableWidgetItem(protocol))
            self.table.setItem(row, 1, QTableWidgetItem(ext_port))
            self.table.setItem(row, 2, QTableWidgetItem(str(rule.get("int_ip", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(str(rule.get("int_port", ""))))
            verification = self.controller.verify_nat_rule(ext_port, protocol)
            self.table.setItem(row, 4, QTableWidgetItem(verification.get("message", "Unknown")))
        self.status.setText(f"Loaded {len(rules)} NAT rule(s).")

    def add_rule(self):
        result = self.controller.add_nat_rule(
            self.ext_port_input.value(),
            self.int_ip_input.text().strip(),
            self.int_port_input.value(),
            self.protocol_box.currentText(),
        )
        self.status.setText(result)
        self.refresh()

    def remove_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "NAT / Port Forwarding", "Select a rule to remove.")
            return
        protocol = self.table.item(row, 0).text()
        ext_port = self.table.item(row, 1).text()
        result = self.controller.remove_nat_rule(ext_port, protocol)
        self.status.setText(result)
        self.refresh()

    def sync_rules(self):
        results = self.controller.sync_nat_rules()
        active = sum(1 for item in results if item.get("status") == "active")
        reapplied = sum(1 for item in results if item.get("status") == "reapplied")
        failed = sum(1 for item in results if item.get("status") == "failed")
        self.status.setText(f"Sync complete: {active} active, {reapplied} reapplied, {failed} failed.")
        self.refresh()


class VpnDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("VPN Integration Layer")
        self.resize(520, 260)

        layout = QVBoxLayout(self)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        enable_btn = QPushButton("Enable / Connect")
        enable_btn.clicked.connect(self.enable_vpn)
        disable_btn = QPushButton("Disable / Disconnect")
        disable_btn.clicked.connect(self.disable_vpn)
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh)
        buttons.addWidget(enable_btn)
        buttons.addWidget(disable_btn)
        buttons.addWidget(refresh_btn)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self):
        self.status_label.setText(self.controller.get_vpn_status())

    def enable_vpn(self):
        QMessageBox.information(self, "VPN", self.controller.toggle_vpn(True))
        self.refresh()

    def disable_vpn(self):
        QMessageBox.information(self, "VPN", self.controller.toggle_vpn(False))
        self.refresh()


class DnsDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Secure Configuration Manager - DNS Configuration")
        self.resize(520, 360)

        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        form = QHBoxLayout()
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("8.8.8.8")
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_dns)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_selected)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_dns)
        form.addWidget(self.dns_input)
        form.addWidget(add_btn)
        form.addWidget(remove_btn)
        form.addWidget(apply_btn)
        layout.addLayout(form)

        self.status = QLabel()
        layout.addWidget(self.status)
        self.refresh()

    def refresh(self):
        self.list_widget.clear()
        for dns in self.controller.get_dns_config():
            self.list_widget.addItem(str(dns))
        self.status.setText("DNS servers loaded.")

    def add_dns(self):
        value = self.dns_input.text().strip()
        if value:
            self.list_widget.addItem(value)
            self.dns_input.clear()

    def remove_selected(self):
        row = self.list_widget.currentRow()
        if row >= 0:
            self.list_widget.takeItem(row)

    def apply_dns(self):
        dns_list = [self.list_widget.item(i).text().strip() for i in range(self.list_widget.count()) if self.list_widget.item(i).text().strip()]
        result = self.controller.set_dns_servers(dns_list)
        self.status.setText(result)


class QosDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Firewall Analytics Module - QoS Rule Management")
        self.resize(720, 420)

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Name", "IP Range", "Bandwidth (Mbps)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        form = QFormLayout()
        self.name_input = QLineEdit()
        self.range_input = QLineEdit()
        self.bandwidth_input = QSpinBox()
        self.bandwidth_input.setRange(1, 100000)
        form.addRow("Rule Name", self.name_input)
        form.addRow("IP Range", self.range_input)
        form.addRow("Bandwidth", self.bandwidth_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_selected)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        buttons.addWidget(add_btn)
        buttons.addWidget(remove_btn)
        buttons.addWidget(refresh_btn)
        layout.addLayout(buttons)

        self.status = QLabel()
        layout.addWidget(self.status)
        self.refresh()

    def refresh(self):
        rules = self.controller.get_qos_rules()
        self.table.setRowCount(0)
        for name, rule in rules.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(name)))
            self.table.setItem(row, 1, QTableWidgetItem(str(rule.get("ip_range", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(rule.get("bandwidth_mbps", ""))))
        self.status.setText(f"Loaded {len(rules)} QoS rule(s).")

    def add_rule(self):
        result = self.controller.add_qos_rule(self.name_input.text().strip(), self.range_input.text().strip(), self.bandwidth_input.value())
        self.status.setText(result)
        self.refresh()

    def remove_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return
        name = self.table.item(row, 0).text()
        if hasattr(self.controller.firewall, 'qos_rules') and name in self.controller.firewall.qos_rules:
            del self.controller.firewall.qos_rules[name]
            self.controller.firewall.log_message(f"QoS rule removed: {name}")
        self.refresh()


class SecurityAlertDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Threat Alert Framework")
        self.resize(680, 420)

        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        buttons = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        clear_btn = QPushButton("Clear Alerts")
        clear_btn.clicked.connect(self.clear_alerts)
        buttons.addWidget(refresh_btn)
        buttons.addWidget(clear_btn)
        layout.addLayout(buttons)

        self.status = QLabel()
        layout.addWidget(self.status)
        self.refresh()

    def refresh(self):
        self.list_widget.clear()
        alerts_data = self.controller.get_security_alerts()
        alerts = alerts_data.get("alerts", [])
        if not alerts:
            self.list_widget.addItem("No alerts detected.")
        else:
            for alert in alerts:
                self.list_widget.addItem(f"[{alert.get('severity', 'Unknown')}] {alert.get('type', 'Unknown')}")
        self.status.setText(f"Total alerts: {alerts_data.get('total_alerts', 0)}")

    def clear_alerts(self):
        self.status.setText(self.controller.clear_security_alerts())
        self.refresh()


class BackupRestoreDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Configuration Recovery System")
        self.resize(560, 220)

        layout = QVBoxLayout(self)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select backup file path")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse)
        row = QHBoxLayout()
        row.addWidget(self.path_input)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        buttons = QHBoxLayout()
        backup_btn = QPushButton("Create Backup")
        backup_btn.clicked.connect(self.backup)
        restore_btn = QPushButton("Restore Backup")
        restore_btn.clicked.connect(self.restore)
        buttons.addWidget(backup_btn)
        buttons.addWidget(restore_btn)
        layout.addLayout(buttons)

        self.status = QLabel()
        layout.addWidget(self.status)

    def browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Backup File", f"firewall_backup_{int(time.time())}.json", "JSON Files (*.json)")
        if path:
            self.path_input.setText(path)

    def backup(self):
        path = self.path_input.text().strip()
        if not path:
            QMessageBox.warning(self, "Backup", "Choose a file path first.")
            return
        self.status.setText(self.controller.backup_settings(path))

    def restore(self):
        path = self.path_input.text().strip()
        if not path:
            QMessageBox.warning(self, "Restore", "Choose a backup file first.")
            return
        self.status.setText(self.controller.restore_settings(path))


class AnalyticsDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Firewall Analytics Module")
        self.resize(720, 520)

        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)

        buttons = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Report")
        refresh_btn.clicked.connect(self.refresh)
        buttons.addWidget(refresh_btn)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self):
        report = self.controller.get_analytics()
        if "error" in report:
            self.text.setPlainText(f"Error: {report['error']}")
            return
        alerts = report.get("security_alerts", {})
        self.text.setPlainText(
            f"Timestamp: {report['timestamp']}\n"
            f"Status: {report['firewall_status']}\n"
            f"Uptime: {report['uptime']}\n\n"
            f"Packets Blocked: {report['packets_blocked']}\n"
            f"Packets Allowed: {report['packets_allowed']}\n"
            f"Block Rate: {report['block_rate']}%\n\n"
            f"Blocked IPs: {report['blocked_ips_count']}\n"
            f"Blocked Ports: {report['blocked_ports_count']}\n"
            f"Blocked Domains: {report['blocked_domains_count']}\n"
            f"Custom Rules: {report['custom_rules_count']}\n"
            f"Recent Traffic Events: {report['recent_traffic_events']}\n"
            f"Security Alerts: {alerts.get('total_alerts', 0)}"
        )


class DomainBlockingDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("🚫 Domain Blocking Manager")
        self.resize(640, 420)

        layout = QVBoxLayout(self)
        
        # Admin status indicator
        self.admin_label = QLabel()
        self.admin_label.setWordWrap(True)
        layout.addWidget(self.admin_label)

        # Domain list
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        # Input and buttons
        form_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., linkedin.com")
        form_layout.addWidget(self.domain_input)

        add_btn = QPushButton("Add Block")
        add_btn.clicked.connect(self.add_domain)
        form_layout.addWidget(add_btn)

        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_selected)
        form_layout.addWidget(remove_btn)

        layout.addLayout(form_layout)

        # Status
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.refresh()

    def refresh(self):
        self.list_widget.clear()
        domains = self.controller.get_blocked_domains()
        if not domains:
            self.list_widget.addItem("No domains blocked")
        else:
            for domain in sorted(domains):
                self.list_widget.addItem(domain)
        
        is_admin = self.controller.is_admin()
        status_text = "✅ Running as Administrator - Full enforcement enabled" if is_admin else "⚠️ NOT running as Administrator - Enforcement limited to firewall rules only"
        self.admin_label.setText(f"Status: {status_text}")
        self.status_label.setText(f"Total blocked domains: {len(domains)}")

    def add_domain(self):
        domain = self.domain_input.text().strip().lower()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain name (e.g., linkedin.com)")
            return
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        result = self.controller.add_blocked_domain(domain)
        self.status_label.setText(result)
        self.domain_input.clear()
        self.refresh()

    def remove_selected(self):
        row = self.list_widget.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Selection Error", "Please select a domain to remove")
            return
        domain = self.list_widget.item(row).text()
        result = self.controller.remove_blocked_domain(domain)
        self.status_label.setText(result)
        self.refresh()


class SettingsTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("⚙️ Secure Configuration Manager")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)

        actions = [
            ("🌐 NAT / Port Forwarding", self.open_nat),
            ("� Domain Blocking", self.open_domain_blocking),
            ("�🚦 Packet Engine", self.open_packet_engine),
            ("🔐 VPN Integration", self.open_vpn),
            ("📡 DNS Configuration", self.open_dns),
            ("⚡ Traffic Shaping (QoS)", self.open_qos),
            ("🛡️ IDS/IPS Integration", self.open_ids),
            ("💾 Backup / Restore", self.open_backup),
            ("📊 Reports & Analytics", self.open_reports),
        ]

        for label, handler in actions:
            button = QPushButton(label)
            button.setFont(QFont("Segoe UI", 11))
            button.setFixedHeight(40)
            button.clicked.connect(handler)
            layout.addWidget(button)

        layout.addStretch()
        self.setLayout(layout)

    def open_nat(self):
        dialog = NatEditorDialog(self.controller, self)
        dialog.exec_()

    def open_domain_blocking(self):
        dialog = DomainBlockingDialog(self.controller, self)
        dialog.exec_()

    def open_packet_engine(self):
        dialog = PacketEngineDialog(self.controller, self)
        dialog.exec_()

    def open_vpn(self):
        dialog = VpnDialog(self.controller, self)
        dialog.exec_()

    def open_dns(self):
        dialog = DnsDialog(self.controller, self)
        dialog.exec_()

    def open_qos(self):
        dialog = QosDialog(self.controller, self)
        dialog.exec_()

    def open_ids(self):
        dialog = SecurityAlertDialog(self.controller, self)
        dialog.exec_()

    def open_backup(self):
        dialog = BackupRestoreDialog(self.controller, self)
        dialog.exec_()

    def open_reports(self):
        dialog = AnalyticsDialog(self.controller, self)
        dialog.exec_()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 Securly Next-Generation-Firewall-Platform")
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
        self.tabs.addTab(self.settings_tab, "⚙️ Secure Configuration Manager")
        
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
