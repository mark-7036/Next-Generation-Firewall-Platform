import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QComboBox, QTableWidget, QTableWidgetItem, QListWidget, QListWidgetItem, QLineEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #2b2d42;
    color: #ffffff;
    font-size: 16px;
}
QFrame {
    background-color: #2b2d42;
    border: none;
}
"""
CARD_STYLE = """
QFrame {
    background-color: #3d3f54;
    border-radius: 14px;
    border: 1.5px solid #4a4d63;
    padding: 32px;
    margin: 8px;
}
"""
TABLE_STYLE = """
QTableWidget {
    background-color: #3d3f54;
    border: 1.5px solid #4a4d63;
    border-radius: 12px;
    gridline-color: #4a4d63;
    color: #ffffff;
    selection-background-color: #1db489;
    font-size: 13px;
}
QTableWidget::item {
    padding: 8px;
    border-bottom: 1px solid #4a4d63;
    font-size: 13px;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #2b2d42;
    color: #ffffff;
    padding: 12px;
    border: none;
    border-bottom: 2px solid #4a4d63;
    font-weight: bold;
    font-size: 13px;
}
"""
BUTTON_STYLE = """
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
"""
SEARCH_STYLE = """
QLineEdit {
    background-color: #2b2d42;
    border: 1px solid #4a4d63;
    border-radius: 6px;
    padding: 8px;
    color: #ffffff;
}
QLineEdit:focus {
    border: 2px solid #1db489;
}
"""
LOG_ITEM_STYLE = """
QListWidget::item {
    padding: 8px;
    border-bottom: 1px solid #4a4d63;
    border-radius: 4px;
    margin: 2px;
}
QListWidget::item:hover {
    background-color: #4a4d63;
}
QListWidget::item:selected {
    background-color: #1db489;
}
"""

class FirewallDashboard(QMainWindow):
    def __init__(self, fw=None):
        super().__init__()
        self.fw = fw
        self.setWindowTitle("Firewall Dashboard")
        self.setStyleSheet(DARK_STYLE)
        self.setGeometry(100, 100, 1500, 900)
        self._init_ui()
        
        # Setup auto-refresh if firewall instance is available
        if self.fw:
            self.refresh_timer = QTimer()
            self.refresh_timer.timeout.connect(self.refresh_data)
            self.refresh_timer.start(2000)  # Refresh every 2 seconds

    def _init_ui(self):
        main = QWidget()
        self.setCentralWidget(main)
        grid = QGridLayout(main)
        grid.setContentsMargins(60, 60, 60, 40)
        grid.setHorizontalSpacing(48)
        grid.setVerticalSpacing(32)

        # --- Sidebar ---
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background-color: #23243a; border-radius: 12px;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 20, 20, 20)
        sidebar_layout.setSpacing(20)
        title = QLabel("Firewall")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #1db489;")
        sidebar_layout.addWidget(title)
        home_btn = QPushButton("Home")
        home_btn.setStyleSheet(BUTTON_STYLE)
        sidebar_layout.addWidget(home_btn)
        rules_btn = QPushButton("Rules")
        rules_btn.setStyleSheet(BUTTON_STYLE)
        sidebar_layout.addWidget(rules_btn)
        sidebar_layout.addStretch(1)
        grid.addWidget(sidebar, 0, 0, 2, 1)

        # --- Firewall Rules Card ---
        rules_frame = QFrame()
        rules_frame.setStyleSheet(CARD_STYLE)
        rules_frame.setMinimumWidth(600)
        rules_frame.setMaximumWidth(600)
        rules_frame.setMinimumHeight(320)
        rules_layout = QVBoxLayout(rules_frame)
        rules_layout.setContentsMargins(32, 32, 32, 32)
        rules_header = QHBoxLayout()
        rules_title = QLabel("Firewall Rules")
        rules_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        rules_title.setStyleSheet("color: #ffffff;")
        rules_header.addWidget(rules_title)
        rules_header.addStretch(1)
        add_rule_btn = QPushButton("ADD RULE")
        add_rule_btn.setStyleSheet(BUTTON_STYLE)
        add_rule_btn.clicked.connect(self.on_add_rule)
        rules_header.addWidget(add_rule_btn)
        rules_layout.addLayout(rules_header)
        self.rules_table = QTableWidget(0, 4)
        self.rules_table.setHorizontalHeaderLabels(["Action", "Source", "Destination", "Protocol"])
        self.rules_table.setStyleSheet(TABLE_STYLE)
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setMinimumHeight(200)
        rules_layout.addWidget(self.rules_table)
        self.populate_rules_table()
        grid.addWidget(rules_frame, 0, 1)

        # --- Live Traffic Card ---
        traffic_frame = QFrame()
        traffic_frame.setStyleSheet(CARD_STYLE)
        traffic_frame.setMinimumWidth(600)
        traffic_frame.setMaximumWidth(600)
        traffic_frame.setMinimumHeight(320)
        traffic_layout = QVBoxLayout(traffic_frame)
        traffic_layout.setContentsMargins(32, 32, 32, 32)
        traffic_header = QHBoxLayout()
        traffic_title = QLabel("Live Traffic")
        traffic_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        traffic_title.setStyleSheet("color: #ffffff;")
        traffic_header.addWidget(traffic_title)
        traffic_header.addStretch(1)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search")
        self.search_input.setStyleSheet(SEARCH_STYLE)
        self.search_input.setFixedWidth(200)
        traffic_header.addWidget(self.search_input)
        traffic_layout.addLayout(traffic_header)
        self.traffic_table = QTableWidget(0, 8)
        self.traffic_table.setHorizontalHeaderLabels(["Time", "Source", "Dest", "Port", "Protocol", "Action", "Size", "Status"])
        self.traffic_table.setStyleSheet(TABLE_STYLE)
        self.traffic_table.horizontalHeader().setStretchLastSection(True)
        self.traffic_table.verticalHeader().setVisible(False)
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setMinimumHeight(200)
        traffic_layout.addWidget(self.traffic_table)
        self.populate_traffic_table()
        grid.addWidget(traffic_frame, 0, 2)

        # --- Security Logs Card ---
        logs_frame = QFrame()
        logs_frame.setStyleSheet(CARD_STYLE)
        logs_frame.setMinimumWidth(1220)
        logs_frame.setMaximumWidth(1220)
        logs_frame.setMinimumHeight(200)
        logs_layout = QVBoxLayout(logs_frame)
        logs_layout.setContentsMargins(32, 32, 32, 32)
        logs_header = QHBoxLayout()
        logs_title = QLabel("Security Logs")
        logs_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        logs_title.setStyleSheet("color: #ffffff;")
        logs_header.addWidget(logs_title)
        logs_header.addStretch(1)
        live_indicator = QLabel("🔴 LIVE")
        live_indicator.setStyleSheet("color: #e74c3c; font-size: 12px; font-weight: bold; margin-left: 10px;")
        logs_header.addWidget(live_indicator)
        log_severity_label = QLabel("High: 2 | Med: 3 | Low: 1")
        log_severity_label.setStyleSheet("color: #8892b0; font-size: 11px; margin-right: 10px;")
        logs_header.addWidget(log_severity_label)
        log_filter = QComboBox()
        log_filter.addItems(["All Logs", "High Severity", "Medium Severity", "Low Severity", "Blocked", "Allowed"])
        log_filter.setStyleSheet(SEARCH_STYLE)
        logs_header.addWidget(log_filter)
        logs_layout.addLayout(logs_header)
        logs_list = QListWidget()
        logs_list.setStyleSheet(f"""
            QListWidget {{
                background-color: #2b2d42;
                border: none;
                color: #8892b0;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 15px;
            }}
            {LOG_ITEM_STYLE}
        """)
        logs_list.setMinimumHeight(100)
        logs_layout.addWidget(logs_list)
        self.populate_logs_list(logs_list)
        export_container = QHBoxLayout()
        export_container.setAlignment(Qt.AlignRight)
        export_logs_btn = QPushButton("📤 Export Logs")
        export_logs_btn.setStyleSheet(BUTTON_STYLE)
        export_logs_btn.clicked.connect(self.on_export_logs)
        export_container.addWidget(export_logs_btn)
        clear_logs_btn = QPushButton("🗑️ Clear")
        clear_logs_btn.setStyleSheet(BUTTON_STYLE)
        clear_logs_btn.clicked.connect(self.on_clear_logs)
        export_container.addWidget(clear_logs_btn)
        logs_layout.addLayout(export_container)
        grid.addWidget(logs_frame, 1, 1, 1, 2)

    def populate_rules_table(self):
        sample_rules = [
            ["ALLOW", "192.168.1.0/24", "Any", "HTTP/HTTPS"],
            ["ALLOW", "Any", "DNS Servers", "DNS"],
            ["BLOCK", "External", "SSH (22)", "TCP"],
            ["ALLOW", "192.168.1.15", "216.58.194.174", "HTTPS"],
            ["BLOCK", "203.0.113.0/24", "Any", "Any"],
        ]
        self.rules_table.setRowCount(len(sample_rules))
        for i, rule in enumerate(sample_rules):
            self.rules_table.setRowHeight(i, 30)
            for j, item in enumerate(rule):
                table_item = QTableWidgetItem(str(item))
                if item == "ALLOW":
                    table_item.setForeground(QColor("#1db489"))
                elif item == "BLOCK":
                    table_item.setForeground(QColor("#e74c3c"))
                else:
                    table_item.setForeground(QColor("#ffffff"))
                self.rules_table.setItem(i, j, table_item)
        self.rules_table.resizeColumnsToContents()

    def populate_traffic_table(self):
        import datetime
        now = datetime.datetime.now()
        sample_traffic = [
            [now.strftime("%H:%M:%S"), "192.168.1.15", "216.58.194.174", "443", "HTTPS", "ALLOW", "2.1KB", "✅"],
            [(now.replace(second=(now.second-5)%60)).strftime("%H:%M:%S"), "192.168.1.22", "8.8.8.8", "53", "DNS", "ALLOW", "512B", "✅"],
            [(now.replace(second=(now.second-12)%60)).strftime("%H:%M:%S"), "192.168.1.15", "140.82.112.4", "443", "HTTPS", "ALLOW", "1.8KB", "✅"],
            [(now.replace(second=(now.second-18)%60)).strftime("%H:%M:%S"), "203.0.113.5", "192.168.1.100", "22", "SSH", "BLOCK", "0B", "🚫"],
            [(now.replace(second=(now.second-25)%60)).strftime("%H:%M:%S"), "192.168.1.33", "172.217.14.110", "80", "HTTP", "ALLOW", "4.2KB", "✅"],
            [(now.replace(second=(now.second-30)%60)).strftime("%H:%M:%S"), "198.51.100.3", "192.168.1.50", "3389", "RDP", "BLOCK", "0B", "🚫"],
        ]
        self.traffic_table.setRowCount(len(sample_traffic))
        for i, row in enumerate(sample_traffic):
            self.traffic_table.setRowHeight(i, 30)
            for j, item in enumerate(row):
                table_item = QTableWidgetItem(str(item))
                if j == 5 and item == "ALLOW":
                    table_item.setForeground(QColor("#1db489"))
                elif j == 5 and item == "BLOCK":
                    table_item.setForeground(QColor("#e74c3c"))
                elif j == 7 and item == "✅":
                    table_item.setForeground(QColor("#1db489"))
                elif j == 7 and item == "🚫":
                    table_item.setForeground(QColor("#e74c3c"))
                else:
                    table_item.setForeground(QColor("#8892b0"))
                self.traffic_table.setItem(i, j, table_item)
        self.traffic_table.resizeColumnsToContents()

    def populate_logs_list(self, logs_list):
        import datetime
        now = datetime.datetime.now()
        sample_logs = [
            f"{now.strftime('%H:%M:%S')} - [HIGH] Port scan detected from 203.0.113.5 → 192.168.1.100",
            f"{(now.replace(minute=(now.minute-2)%60)).strftime('%H:%M:%S')} - [MEDIUM] Multiple failed login attempts from 198.51.100.3",
            f"{(now.replace(minute=(now.minute-5)%60)).strftime('%H:%M:%S')} - [LOW] DNS query blocked: malicious-domain.com",
            f"{(now.replace(minute=(now.minute-8)%60)).strftime('%H:%M:%S')} - [HIGH] Suspicious traffic pattern detected",
            f"{(now.replace(minute=(now.minute-12)%60)).strftime('%H:%M:%S')} - [MEDIUM] Firewall rule updated: Block SSH from external",
        ]
        logs_list.clear()
        for log in sample_logs:
            item = QListWidgetItem(log)
            if "[HIGH]" in log:
                item.setForeground(QColor("#e74c3c"))
                item.setBackground(QColor("#4a1e1e"))
            elif "[MEDIUM]" in log:
                item.setForeground(QColor("#f39c12"))
                item.setBackground(QColor("#4a3a1e"))
            elif "[LOW]" in log:
                item.setForeground(QColor("#8892b0"))
            else:
                item.setForeground(QColor("#8892b0"))
            logs_list.addItem(item)

    def on_add_rule(self):
        """Handle adding a new firewall rule"""
        QMessageBox.information(self, "Add Rule", "Rule management feature coming soon!")

    def on_export_logs(self):
        """Handle exporting logs"""
        if self.fw:
            try:
                self.fw.export_logs("firewall_logs_export.txt")
                QMessageBox.information(self, "Export", "Logs exported to firewall_logs_export.txt")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to export logs: {e}")
        else:
            QMessageBox.information(self, "Export", "No firewall instance available")

    def on_clear_logs(self):
        """Handle clearing logs"""
        reply = QMessageBox.question(self, "Clear Logs", "Are you sure you want to clear all logs?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.fw:
                try:
                    self.fw.clear_logs()
                    QMessageBox.information(self, "Success", "Logs cleared!")
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to clear logs: {e}")
            else:
                QMessageBox.information(self, "Clear Logs", "No firewall instance available")

    def refresh_data(self):
        """Refresh GUI data from firewall backend"""
        if not self.fw:
            return
        try:
            # Could update traffic table, rules, logs here
            # This is a placeholder for future dynamic updates
            pass
        except Exception as e:
            print(f"Error refreshing data: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
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
    app.setPalette(palette)
    dash = FirewallDashboard()
    dash.show()
    sys.exit(app.exec_())
