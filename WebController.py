import sys
from PyQt5.QtWidgets import QMessageBox, QDialog, QFileSystemModel, QTreeView, QApplication, QMainWindow, QLabel, QLineEdit, QTextEdit, QPushButton, QFrame, QVBoxLayout, QWidget, QFileDialog, QTreeView, QSplitter
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal, QModelIndex, QDir
from PyQt5.QtGui import QStandardItemModel, QStandardItem
import requests
import subprocess
from datetime import datetime
import time
import qdarkstyle
import paramiko
from cryptography.fernet import Fernet
import json
import os

is_maintenance_mode = False


cipher = Fernet(b"OnbJ_tSt9gIuNLgCoHCoJT7EoWm_Dovoe23gOIlQDfg=")

# Function to encrypt data
def encrypt_data(data, cipher):
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data, cipher):
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()


class StatusCheckThread(QThread):
    status_checked = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        while True:
            self.check_website_status()
            time.sleep(60)  # Check status every 60 seconds

    def check_website_status(self):
        try:
            start_time = time.time()  # Record the start time
            response = requests.get(self.url)
            end_time = time.time()  # Record the end time
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status_messages = {
                200: "Website is accessible.",
                301: "Website has permanently moved.",
                400: "Bad request. Website not found.",
                403: "Access to the website is forbidden.",
                404: "Website not found.",
                500: "Internal server error. Website is down.",
                503: "Website is in maintenance mode.",
                # Add more status codes and messages as needed
            }

            default_message = "Unknown status code."

            status = status_messages.get(response.status_code, default_message)

            data = {
                "Timestamp": timestamp,
                "Website": self.url,
                "Status": status,
                "Response_code": response.status_code,
                "Response_time": end_time - start_time,
                "Request_type": response.request.method,  # Get the request type
                "Content-Type:": response.headers.get('Content-Type'),
                "Content-Length:": response.headers.get('Content-Length'),
                "Server:": response.headers.get('Server'),
                "Date:": response.headers.get('Date'),
                "Connection_type": response.headers.get("connection"),  # Get the connection type
                "Https": self.url.startswith("https://")  # Check if the website uses HTTPS
            }

            file_name = self.url.replace("http://", "").replace("https://", "").replace("/", "").replace(".", "_") + ".json"
            file_path = os.path.join("logs", file_name)  # Construct the file path within the "logs" directory

            # Check if the file already exists
            if os.path.exists(file_path):
                # Load existing data
                with open(file_path, "r") as file:
                    existing_data = json.load(file)

                # Check if 'logs' key exists in existing data
                if 'logs' in existing_data:
                    # Append new data to existing 'logs' list
                    existing_data['logs'].append(data)
                else:
                    # Create 'logs' key and initialize it with a list containing the first data entry
                    existing_data['logs'] = [data]

                # Save updated JSON data to file with proper formatting
                with open(file_path, "w") as file:
                    json.dump(existing_data, file, indent=4)
            else:
                # Save JSON data to file with 'logs' key and proper formatting
                with open(file_path, "w") as file:
                    json.dump({'logs': [data]}, file, indent=4)

            self.status_checked.emit(status)
            
            self.error_occurred = False  # Reset the error state
        except Exception as e:
            if not getattr(self, 'error_occurred', False):
                self.error_occurred = True
                error_dialog = QDialog()
                error_dialog.setWindowTitle("Error")
                layout = QVBoxLayout()
                error_label = QLabel("An error occurred: {}".format(str(e)))
                layout.addWidget(error_label)
                error_dialog.setLayout(layout)
                error_dialog.exec_()


class SshFileListThread(QThread):
    file_list_ready = pyqtSignal(list)

    def __init__(self, host, port, username, password, directory):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.directory = directory

    def run(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.host, port=self.port, username=self.username, password=self.password)
            sftp = ssh.open_sftp()
            file_list = sftp.listdir(self.directory)
            self.file_list_ready.emit(file_list)
            sftp.close()
            ssh.close()
        except paramiko.AuthenticationException:
            print("Authentication failed.")
        except paramiko.SSHException as e:
            print(f"SSH error: {str(e)}")
        except paramiko.socket.error as e:
            print(f"Socket error: {str(e)}")
        except paramiko.SFTPError as e:
            print(f"SFTP error: {str(e)}")

class WebControllerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Spell Controller")
        self.setFixedSize(800, 800)  # Set a fixed size for the window
        self.setStyleSheet(qdarkstyle.load_stylesheet())

        self.create_widgets()
        self.create_layout()

        self.status_check_thread = StatusCheckThread(self.website_entry.text())
        self.status_check_thread.status_checked.connect(self.output_message)
        self.status_check_thread.start()

        self.website_entry.textChanged.connect(self.update_status_check_thread_url)

    def update_status_check_thread_url(self):
        self.status_check_thread.url = self.website_entry.text()

    def create_widgets(self):
        self.output_label = QLabel("Output:", self)
        self.output_label.setStyleSheet("font-weight: bold; font-size: 12pt")
        self.console_text = QTextEdit(self)
        self.console_text.setReadOnly(True)
        self.header_label = QLabel("Spell Controller", self)
        self.header_label.setStyleSheet("font-weight: bold; font-size: 16pt")
        self.website_label = QLabel("Website URL:", self)
        self.website_entry = QLineEdit(self)
        self.website_entry.setText("https://google.com/")
        self.host_label = QLabel("Host:", self)
        self.host_entry = QLineEdit(self)
        self.port_label = QLabel("Port:", self)
        self.port_entry = QLineEdit(self)
        self.username_label = QLabel("Username:", self)
        self.username_entry = QLineEdit(self)
        self.password_label = QLabel("Password:", self)
        self.password_entry = QLineEdit(self)
        self.directory_label = QLabel("Directory:", self)
        self.directory_entry = QLineEdit(self)
        self.appname_label = QLabel("App Name:", self)
        self.appname_entry = QLineEdit(self)
        self.gitrepo_label = QLabel("Git Repo:", self)
        self.gitrepo_entry = QLineEdit(self)
        self.btn_deploy_git = QPushButton("Deploy Git", self)
        self.btn_check_status = QPushButton("Check Status", self)
        self.btn_maintenance_toggle = QPushButton("Maintenance On", self)
        self.btn_maintenance_toggle.setStyleSheet("background-color: green")
        self.btn_migrate_origin = QPushButton("Migrate: Standard", self)
        self.btn_migrate_fresh = QPushButton("Migrate: Fresh", self)
        self.btn_generate_report = QPushButton("Check Response Time", self)

        self.btn_deploy_git.setEnabled(False)
        self.btn_maintenance_toggle.setEnabled(False)
        self.btn_migrate_origin.setEnabled(False)
        self.btn_migrate_fresh.setEnabled(False)
        self.btn_generate_report.setEnabled(False)

        self.website_entry.textChanged.connect(self.update_button_state)

        self.btn_deploy_git.clicked.connect(self.deploy_git)
        self.btn_check_status.clicked.connect(self.check_status)
        self.btn_maintenance_toggle.clicked.connect(self.toggle_maintenance_mode)
        self.btn_migrate_origin.clicked.connect(self.migrate_origin)
        self.btn_migrate_fresh.clicked.connect(self.migrate_fresh)
        self.btn_generate_report.clicked.connect(self.generate_graph_report)

        self.btn_deploy_git.setObjectName("DeployButton")  # Set an object name for the button
        self.btn_check_status.setObjectName("StatusButton")  # Set an object name for the button
        self.btn_maintenance_toggle.setObjectName("MaintenanceButton")  # Set an object name for the button
        self.btn_migrate_origin.setObjectName("MigrateOriginButton")  # Set an object name for the button
        self.btn_migrate_fresh.setObjectName("MigrateFreshButton")  # Set an object name for the button
        self.btn_generate_report.setObjectName("GenerateButton")  # Set an object name for the button

        self.btn_deploy_git.setCursor(Qt.PointingHandCursor)  # Set the cursor to a pointing hand
        self.btn_check_status.setCursor(Qt.PointingHandCursor)  # Set the cursor to a pointing hand
        self.btn_maintenance_toggle.setCursor(Qt.PointingHandCursor)  # Set the cursor to a pointing hand
        self.btn_migrate_origin.setCursor(Qt.PointingHandCursor)
        self.btn_migrate_fresh.setCursor(Qt.PointingHandCursor)
        self.btn_generate_report.setCursor(Qt.PointingHandCursor)  # Set an object name for the button

        # Load and Save buttons
        self.btn_load = QPushButton("Load", self)
        self.btn_save = QPushButton("Save", self)

        self.btn_load.clicked.connect(self.load_fields)
        self.btn_save.clicked.connect(self.save_fields)

        self.ssh_file_tree = QTreeView()
        self.ssh_file_tree.doubleClicked.connect(self.open_file)
        self.ssh_file_model = QStandardItemModel()
        self.ssh_file_tree.setModel(self.ssh_file_model)
        self.ssh_file_tree.setColumnWidth(0, 250)


    def create_layout(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        left_widget = QWidget(splitter)
        left_layout = QVBoxLayout(left_widget)
        left_widget.setLayout(left_layout)

        right_widget = QWidget(splitter)
        right_layout = QVBoxLayout(right_widget)
        right_widget.setLayout(right_layout)

        left_layout.addWidget(self.header_label)

        website_frame = QFrame(left_widget)
        website_layout = QVBoxLayout(website_frame)
        website_layout.addWidget(self.website_label)
        website_layout.addWidget(self.website_entry)
        left_layout.addWidget(website_frame)

        credentials_frame = QFrame(left_widget)
        credentials_layout = QVBoxLayout(credentials_frame)
        credentials_layout.addWidget(self.host_label)
        credentials_layout.addWidget(self.host_entry)
        credentials_layout.addWidget(self.port_label)
        credentials_layout.addWidget(self.port_entry)
        credentials_layout.addWidget(self.username_label)
        credentials_layout.addWidget(self.username_entry)
        credentials_layout.addWidget(self.password_label)
        credentials_layout.addWidget(self.password_entry)
        credentials_layout.addWidget(self.directory_label)
        credentials_layout.addWidget(self.directory_entry)
        credentials_layout.addWidget(self.appname_label)
        credentials_layout.addWidget(self.appname_entry)
        credentials_layout.addWidget(self.gitrepo_label)
        credentials_layout.addWidget(self.gitrepo_entry)
        left_layout.addWidget(credentials_frame)

        buttons_frame = QFrame(left_widget)
        buttons_layout = QVBoxLayout(buttons_frame)
        buttons_layout.addWidget(self.btn_deploy_git)
        buttons_layout.addWidget(self.btn_check_status)
        buttons_layout.addWidget(self.btn_maintenance_toggle)
        buttons_layout.addWidget(self.btn_migrate_origin)
        buttons_layout.addWidget(self.btn_migrate_fresh)
        buttons_layout.addWidget(self.btn_generate_report)
        buttons_layout.addWidget(self.btn_load)
        buttons_layout.addWidget(self.btn_save)
        left_layout.addWidget(buttons_frame)

        left_layout.addStretch(1)  # Add stretchable spacer

        left_layout.addWidget(self.output_label)
        left_layout.addWidget(self.console_text)

        right_layout.addWidget(self.ssh_file_tree)

    def update_ssh_file_tree(self, file_list):
        self.ssh_file_model.clear()
        self.ssh_file_model.setHorizontalHeaderLabels(["Files"])
        self.add_items_to_model(self.ssh_file_model, file_list, self.ssh_file_model.invisibleRootItem())

    def add_items_to_model(self, model, items, parent_item):
        for item in items:
            item_name = QStandardItem(item)
            parent_item.appendRow(item_name)

    def refresh_ssh_file_tree(self):
        host = self.host_entry.text()
        port = int(self.port_entry.text())
        username = self.username_entry.text()
        password = self.password_entry.text()
        directory = self.directory_entry.text()

        self.file_list_thread = SshFileListThread(host, port, username, password, directory)
        self.file_list_thread.file_list_ready.connect(self.update_ssh_file_tree)
        self.file_list_thread.start()

    def output_message(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        self.console_text.append(timestamp + message)

    def toggle_maintenance_mode(self):
        global is_maintenance_mode
        is_maintenance_mode = not is_maintenance_mode
        if is_maintenance_mode:
            self.execute_script("core/maintenance-on.py", self.host_entry.text(), self.port_entry.text(), self.username_entry.text(),
                                self.password_entry.text(), self.directory_entry.text(), self.appname_entry.text())
            self.btn_maintenance_toggle.setText("Maintenance Off")
            self.btn_maintenance_toggle.setStyleSheet("background-color: red")
        else:
            self.execute_script("core/maintenance-off.py", self.host_entry.text(), self.port_entry.text(), self.username_entry.text(),
                                self.password_entry.text(), self.directory_entry.text(), self.appname_entry.text())
            self.btn_maintenance_toggle.setText("Maintenance On")
            self.btn_maintenance_toggle.setStyleSheet("background-color: green")

    def migrate_origin(self):
        self.execute_script("core/migrate-origin.py", self.host_entry.text(), self.port_entry.text(), self.username_entry.text(),
                                self.password_entry.text(), self.directory_entry.text(), self.appname_entry.text())

    def migrate_fresh(self):
        self.execute_script("core/migrate-fresh.py", self.host_entry.text(), self.port_entry.text(), self.username_entry.text(),
                                self.password_entry.text(), self.directory_entry.text(), self.appname_entry.text())

    def generate_graph_report(self):
        file_name = self.website_entry.text().replace("http://", "").replace("https://", "").replace("/", "").replace(".", "_") + ".json"
        file_path = os.path.join("logs", file_name)  # Construct the file path within the "logs" directory
        os.system(f'pythonw core/checkResponse.py --location {file_path}')

    def deploy_git(self):
        self.execute_script("core/deploy.py", self.host_entry.text(), self.port_entry.text(), self.username_entry.text(),
                            self.password_entry.text(), self.directory_entry.text(), self.appname_entry.text(),
                            self.gitrepo_entry.text())

    def check_status(self):
        url = self.website_entry.text()
        try:
            response = requests.get(url)
            if response.status_code == 503:
                self.output_message("Website is in maintenance mode.")
            else:
                self.output_message("Website is accessible.")
        except requests.exceptions.RequestException as e:
            self.output_message(f"Error: {str(e)}")

    def execute_script(self, script_name, *args):
        command = ["python", script_name] + list(args)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if output:
            self.output_message(output.decode())
        if error:
            self.output_message(error.decode())

    def update_button_state(self):
        url = self.website_entry.text()
        self.btn_deploy_git.setEnabled(url != "")
        self.btn_migrate_origin.setEnabled(url != "")
        self.btn_migrate_fresh.setEnabled(url != "")
        self.btn_maintenance_toggle.setEnabled(url != "")
        self.btn_generate_report.setEnabled(url != "")

    def save_fields(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Fields", "", "Spell Controller Files (*.spell)")
        if file_path:
            if not file_path.endswith(".spell"):
                file_path += ".spell"
            fields = [
                self.website_entry.text(),
                self.host_entry.text(),
                self.port_entry.text(),
                self.username_entry.text(),
                self.password_entry.text(),
                self.directory_entry.text(),
                self.appname_entry.text(),
                self.gitrepo_entry.text()
            ]
            encrypted_fields = [encrypt_data(field, cipher) for field in fields]
            with open(file_path, "wb") as file:
                for encrypted_field in encrypted_fields:
                    file.write(encrypted_field + b'\n')  # Add a newline character after each field

    def load_fields(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Fields", "", "Spell Controller Files (*.spell)")
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    encrypted_fields = file.readlines()
                    decrypted_fields = [decrypt_data(encrypted_field, cipher) for encrypted_field in encrypted_fields]
                    if len(decrypted_fields) == 8:
                        (
                            website,
                            host,
                            port,
                            username,
                            password,
                            directory,
                            appname,
                            gitrepo,
                        ) = decrypted_fields
                        self.website_entry.setText(website)
                        self.host_entry.setText(host)
                        self.port_entry.setText(port)
                        self.username_entry.setText(username)
                        self.password_entry.setText(password)
                        self.directory_entry.setText(directory)
                        self.appname_entry.setText(appname)
                        self.gitrepo_entry.setText(gitrepo)

                        self.refresh_ssh_file_tree()  # Refresh the file tree
                    else:
                        QMessageBox.critical(self, "Invalid Spell File", "The selected file is invalid or corrupted.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred while loading the fields:\n{str(e)}")



    def open_file(self, index):
        file_path = self.ssh_file_model.data(index, Qt.UserRole)

        if file_path:
            with open(file_path, "r") as file:
                content = file.read()
                text_edit = QTextEdit()
                text_edit.setWindowTitle(file_path)
                text_edit.setPlainText(content)
                text_edit.show()
                
if __name__ == "__main__":
    app = QApplication(sys.argv)

    main_window = WebControllerWindow()

    main_window.show()
    sys.exit(app.exec_())