#!/usr/bin/env python3
"""
Cisco AI Agent Installer
A professional graphical installer for deploying local agents
"""

import sys
import os
import json
import subprocess
import threading
import time
import requests
import hashlib
from datetime import datetime
from pathlib import Path

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
        QStackedWidget, QFrame, QMessageBox, QCheckBox, QComboBox,
        QGroupBox, QGridLayout, QSpacerItem, QSizePolicy
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QPixmap, QIcon
except ImportError:
    print("PyQt5 is required. Install with: pip install PyQt5")
    sys.exit(1)

# Configuration
AGENT_VERSION = "1.0.0"
AGENT_NAME = "Cisco AI Agent"
BACKEND_URL = "https://your-backend-url.com"  # Will be updated during installation

class InstallationThread(QThread):
    """Background thread for installation process"""
    progress_updated = pyqtSignal(int, str)
    installation_complete = pyqtSignal(bool, str)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        
    def run(self):
        try:
            # Step 1: Validate configuration
            self.progress_updated.emit(10, "Validating configuration...")
            if not self.validate_config():
                self.installation_complete.emit(False, "Invalid configuration")
                return
                
            # Step 2: Create installation directory
            self.progress_updated.emit(20, "Creating installation directory...")
            install_dir = self.create_install_directory()
            
            # Step 3: Download agent files
            self.progress_updated.emit(30, "Downloading agent files...")
            if not self.download_agent_files(install_dir):
                self.installation_complete.emit(False, "Failed to download agent files")
                return
                
            # Step 4: Install dependencies
            self.progress_updated.emit(50, "Installing Python dependencies...")
            if not self.install_dependencies(install_dir):
                self.installation_complete.emit(False, "Failed to install dependencies")
                return
                
            # Step 5: Configure agent
            self.progress_updated.emit(70, "Configuring agent...")
            if not self.configure_agent(install_dir):
                self.installation_complete.emit(False, "Failed to configure agent")
                return
                
            # Step 6: Create service
            self.progress_updated.emit(85, "Creating system service...")
            if not self.create_service(install_dir):
                self.installation_complete.emit(False, "Failed to create system service")
                return
                
            # Step 7: Start service
            self.progress_updated.emit(95, "Starting agent service...")
            if not self.start_service():
                self.installation_complete.emit(False, "Failed to start agent service")
                return
                
            self.progress_updated.emit(100, "Installation completed successfully!")
            self.installation_complete.emit(True, "Installation completed successfully!")
            
        except Exception as e:
            self.installation_complete.emit(False, f"Installation failed: {str(e)}")
    
    def validate_config(self):
        """Validate installation configuration"""
        required_fields = ['backend_url', 'agent_token', 'agent_name']
        for field in required_fields:
            if not self.config.get(field):
                return False
        return True
    
    def create_install_directory(self):
        """Create installation directory"""
        install_dir = Path.home() / "cisco_ai_agent"
        install_dir.mkdir(exist_ok=True)
        return install_dir
    
    def download_agent_files(self, install_dir):
        """Download agent files from backend"""
        try:
            # Download main agent script
            agent_url = f"{self.config['backend_url']}/api/v1/agents/download"
            response = requests.get(agent_url, headers={
                'X-Agent-Token': self.config['agent_token']
            })
            
            if response.status_code == 200:
                agent_script = install_dir / "cisco_ai_agent.py"
                with open(agent_script, 'w') as f:
                    f.write(response.text)
                return True
            return False
        except Exception as e:
            print(f"Error downloading agent files: {e}")
            return False
    
    def install_dependencies(self, install_dir):
        """Install Python dependencies"""
        try:
            requirements = [
                "requests>=2.25.0",
                "pysnmp>=4.4.0",
                "paramiko>=2.7.0",
                "websocket-client>=1.0.0",
                "psutil>=5.8.0"
            ]
            
            for req in requirements:
                subprocess.run([sys.executable, "-m", "pip", "install", req], 
                             check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def configure_agent(self, install_dir):
        """Configure agent with provided settings"""
        try:
            config = {
                "backend_url": self.config['backend_url'],
                "agent_token": self.config['agent_token'],
                "agent_name": self.config['agent_name'],
                "version": AGENT_VERSION,
                "install_dir": str(install_dir),
                "created_at": datetime.now().isoformat()
            }
            
            config_file = install_dir / "config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error configuring agent: {e}")
            return False
    
    def create_service(self, install_dir):
        """Create system service for the agent"""
        try:
            if sys.platform == "win32":
                return self.create_windows_service(install_dir)
            else:
                return self.create_linux_service(install_dir)
        except Exception as e:
            print(f"Error creating service: {e}")
            return False
    
    def create_windows_service(self, install_dir):
        """Create Windows service"""
        try:
            # Create batch file to run agent
            batch_file = install_dir / "start_agent.bat"
            with open(batch_file, 'w') as f:
                f.write(f'@echo off\n')
                f.write(f'cd /d "{install_dir}"\n')
                f.write(f'python cisco_ai_agent.py\n')
                f.write(f'pause\n')
            
            # Create Windows service using sc command
            service_name = "CiscoAIAgent"
            cmd = [
                "sc", "create", service_name,
                "binPath=", f'"{install_dir}\\start_agent.bat"',
                "start=", "auto",
                "DisplayName=", "Cisco AI Agent"
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def create_linux_service(self, install_dir):
        """Create Linux systemd service"""
        try:
            service_content = f"""[Unit]
Description=Cisco AI Agent
After=network.target

[Service]
Type=simple
User={os.getenv('USER')}
WorkingDirectory={install_dir}
ExecStart={sys.executable} {install_dir}/cisco_ai_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            
            service_file = Path("/etc/systemd/system/cisco-ai-agent.service")
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Reload systemd and enable service
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", "cisco-ai-agent"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def start_service(self):
        """Start the agent service"""
        try:
            if sys.platform == "win32":
                subprocess.run(["sc", "start", "CiscoAIAgent"], check=True)
            else:
                subprocess.run(["sudo", "systemctl", "start", "cisco-ai-agent"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False


class WelcomePage(QWidget):
    """Welcome page of the installer"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Logo and title
        title_label = QLabel(AGENT_NAME)
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        subtitle_label = QLabel(f"Version {AGENT_VERSION}")
        subtitle_label.setFont(QFont("Arial", 12))
        subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle_label)
        
        layout.addSpacing(30)
        
        # Welcome message
        welcome_text = QLabel(
            "Welcome to the Cisco AI Agent installer!\n\n"
            "This wizard will help you install and configure a local agent "
            "that can discover and monitor network devices in your environment.\n\n"
            "The agent will:\n"
            "• Discover network devices using SNMP and SSH\n"
            "• Collect device configurations and status\n"
            "• Send data securely to your Cisco AI backend\n"
            "• Run as a system service for continuous operation"
        )
        welcome_text.setWordWrap(True)
        welcome_text.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_text)
        
        layout.addStretch()
        
        # System requirements
        requirements_group = QGroupBox("System Requirements")
        requirements_layout = QVBoxLayout()
        
        requirements = [
            "✓ Python 3.7 or higher",
            "✓ Internet connection for initial setup",
            "✓ Administrative privileges (for service installation)",
            "✓ Network access to target devices"
        ]
        
        for req in requirements:
            req_label = QLabel(req)
            requirements_layout.addWidget(req_label)
        
        requirements_group.setLayout(requirements_layout)
        layout.addWidget(requirements_group)
        
        self.setLayout(layout)


class ConfigurationPage(QWidget):
    """Configuration page for agent settings"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title_label = QLabel("Agent Configuration")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title_label)
        
        # Backend URL
        backend_group = QGroupBox("Backend Connection")
        backend_layout = QGridLayout()
        
        backend_layout.addWidget(QLabel("Backend URL:"), 0, 0)
        self.backend_url_edit = QLineEdit()
        self.backend_url_edit.setPlaceholderText("https://your-backend-url.com")
        backend_layout.addWidget(self.backend_url_edit, 0, 1)
        
        backend_group.setLayout(backend_layout)
        layout.addWidget(backend_group)
        
        # Agent Token
        token_group = QGroupBox("Authentication")
        token_layout = QGridLayout()
        
        token_layout.addWidget(QLabel("Agent Token:"), 0, 0)
        self.agent_token_edit = QLineEdit()
        self.agent_token_edit.setEchoMode(QLineEdit.Password)
        self.agent_token_edit.setPlaceholderText("Enter your agent token")
        token_layout.addWidget(self.agent_token_edit, 0, 1)
        
        token_group.setLayout(token_layout)
        layout.addWidget(token_group)
        
        # Agent Settings
        agent_group = QGroupBox("Agent Settings")
        agent_layout = QGridLayout()
        
        agent_layout.addWidget(QLabel("Agent Name:"), 0, 0)
        self.agent_name_edit = QLineEdit()
        self.agent_name_edit.setPlaceholderText("Enter a descriptive name for this agent")
        agent_layout.addWidget(self.agent_name_edit, 0, 1)
        
        agent_layout.addWidget(QLabel("Discovery Methods:"), 1, 0)
        self.snmp_checkbox = QCheckBox("SNMP")
        self.snmp_checkbox.setChecked(True)
        self.ssh_checkbox = QCheckBox("SSH/CLI")
        self.ssh_checkbox.setChecked(True)
        
        discovery_layout = QHBoxLayout()
        discovery_layout.addWidget(self.snmp_checkbox)
        discovery_layout.addWidget(self.ssh_checkbox)
        discovery_layout.addStretch()
        agent_layout.addLayout(discovery_layout, 1, 1)
        
        agent_group.setLayout(agent_layout)
        layout.addWidget(agent_group)
        
        # Advanced Options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QGridLayout()
        
        advanced_layout.addWidget(QLabel("Log Level:"), 0, 0)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["INFO", "DEBUG", "WARNING", "ERROR"])
        advanced_layout.addWidget(self.log_level_combo, 0, 1)
        
        advanced_layout.addWidget(QLabel("Heartbeat Interval (seconds):"), 1, 0)
        self.heartbeat_edit = QLineEdit("30")
        advanced_layout.addWidget(self.heartbeat_edit, 1, 1)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def get_config(self):
        """Get configuration from form"""
        return {
            'backend_url': self.backend_url_edit.text().strip(),
            'agent_token': self.agent_token_edit.text().strip(),
            'agent_name': self.agent_name_edit.text().strip(),
            'discovery_methods': {
                'snmp': self.snmp_checkbox.isChecked(),
                'ssh': self.ssh_checkbox.isChecked()
            },
            'log_level': self.log_level_combo.currentText(),
            'heartbeat_interval': int(self.heartbeat_edit.text() or "30")
        }
    
    def validate(self):
        """Validate configuration"""
        config = self.get_config()
        if not config['backend_url']:
            return False, "Backend URL is required"
        if not config['agent_token']:
            return False, "Agent token is required"
        if not config['agent_name']:
            return False, "Agent name is required"
        return True, ""


class InstallationPage(QWidget):
    """Installation progress page"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title_label = QLabel("Installing Cisco AI Agent")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Status text
        self.status_label = QLabel("Preparing installation...")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Log output
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(200)
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        self.setLayout(layout)
    
    def update_progress(self, value, message):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def installation_finished(self, success, message):
        """Handle installation completion"""
        if success:
            self.status_label.setText("Installation completed successfully!")
            self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        else:
            self.status_label.setText("Installation failed!")
            self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {message}")


class CompletionPage(QWidget):
    """Installation completion page"""
    def __init__(self, success=True, parent=None):
        super().__init__(parent)
        self.success = success
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        if self.success:
            # Success icon and message
            icon_label = QLabel("✓")
            icon_label.setFont(QFont("Arial", 48))
            icon_label.setStyleSheet("color: green;")
            icon_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(icon_label)
            
            title_label = QLabel("Installation Completed!")
            title_label.setFont(QFont("Arial", 18, QFont.Bold))
            title_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(title_label)
            
            message_label = QLabel(
                "The Cisco AI Agent has been successfully installed and started.\n\n"
                "The agent is now running as a system service and will automatically:\n"
                "• Start when the system boots\n"
                "• Discover network devices\n"
                "• Send data to your backend\n"
                "• Restart automatically if it encounters issues\n\n"
                "You can monitor the agent status in your web interface."
            )
            message_label.setWordWrap(True)
            message_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(message_label)
        else:
            # Error icon and message
            icon_label = QLabel("✗")
            icon_label.setFont(QFont("Arial", 48))
            icon_label.setStyleSheet("color: red;")
            icon_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(icon_label)
            
            title_label = QLabel("Installation Failed")
            title_label.setFont(QFont("Arial", 18, QFont.Bold))
            title_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(title_label)
            
            message_label = QLabel(
                "The installation encountered an error. Please check the log above "
                "for details and try again.\n\n"
                "Common issues:\n"
                "• Insufficient permissions (run as administrator)\n"
                "• Network connectivity problems\n"
                "• Invalid configuration parameters"
            )
            message_label.setWordWrap(True)
            message_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(message_label)
        
        layout.addStretch()
        self.setLayout(layout)


class AgentInstaller(QMainWindow):
    """Main installer window"""
    def __init__(self):
        super().__init__()
        self.current_page = 0
        self.config = {}
        self.installation_thread = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle(f"{AGENT_NAME} Installer")
        self.setFixedSize(600, 500)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint)
        
        # Center window
        self.center_window()
        
        # Create stacked widget for pages
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create pages
        self.welcome_page = WelcomePage()
        self.config_page = ConfigurationPage()
        self.installation_page = InstallationPage()
        self.completion_page = None
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.welcome_page)
        self.stacked_widget.addWidget(self.config_page)
        self.stacked_widget.addWidget(self.installation_page)
        
        # Create navigation buttons
        self.create_navigation_buttons()
        
        # Show first page
        self.show_page(0)
    
    def center_window(self):
        """Center the window on screen"""
        screen = QApplication.desktop().screenGeometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )
    
    def create_navigation_buttons(self):
        """Create navigation button layout"""
        # Create button container
        button_container = QWidget()
        button_layout = QHBoxLayout()
        
        # Back button
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.previous_page)
        button_layout.addWidget(self.back_button)
        
        button_layout.addStretch()
        
        # Next/Install/Finish button
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self.next_page)
        button_layout.addWidget(self.next_button)
        
        button_container.setLayout(button_layout)
        
        # Add button container to main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(button_container)
        
        # Create central widget with layout
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
    
    def show_page(self, page_index):
        """Show specific page and update navigation"""
        self.current_page = page_index
        self.stacked_widget.setCurrentIndex(page_index)
        
        # Update button states
        self.back_button.setVisible(page_index > 0)
        
        if page_index == 0:
            self.next_button.setText("Next")
        elif page_index == 1:
            self.next_button.setText("Install")
        elif page_index == 2:
            self.next_button.setText("Installing...")
            self.next_button.setEnabled(False)
            self.back_button.setEnabled(False)
        else:
            self.next_button.setText("Finish")
    
    def next_page(self):
        """Handle next button click"""
        if self.current_page == 0:
            # Welcome page -> Configuration page
            self.show_page(1)
        elif self.current_page == 1:
            # Configuration page -> Installation page
            if self.validate_configuration():
                self.show_page(2)
                self.start_installation()
        elif self.current_page == 2:
            # Installation page -> Completion page
            pass  # Handled by installation thread
        else:
            # Completion page -> Close installer
            self.close()
    
    def previous_page(self):
        """Handle back button click"""
        if self.current_page > 0:
            self.show_page(self.current_page - 1)
    
    def validate_configuration(self):
        """Validate configuration before installation"""
        is_valid, error_message = self.config_page.validate()
        if not is_valid:
            QMessageBox.warning(self, "Configuration Error", error_message)
            return False
        return True
    
    def start_installation(self):
        """Start the installation process"""
        # Get configuration
        self.config = self.config_page.get_config()
        
        # Create and start installation thread
        self.installation_thread = InstallationThread(self.config)
        self.installation_thread.progress_updated.connect(
            self.installation_page.update_progress
        )
        self.installation_thread.installation_complete.connect(
            self.installation_finished
        )
        self.installation_thread.start()
    
    def installation_finished(self, success, message):
        """Handle installation completion"""
        # Create completion page
        self.completion_page = CompletionPage(success)
        self.stacked_widget.addWidget(self.completion_page)
        
        # Show completion page
        self.show_page(3)
        
        # Re-enable navigation
        self.next_button.setEnabled(True)
        self.back_button.setEnabled(True)


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show installer
    installer = AgentInstaller()
    installer.show()
    
    # Run application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 