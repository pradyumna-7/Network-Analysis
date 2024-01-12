import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QFont, QCursor
from PyQt5.QtCore import QTimer, Qt
import wmi
import os

class USBScannerGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.wmi_service = wmi.WMI()
        self.previous_devices = {}
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_usb_devices)
        self.timer.start(1000)  # Set the update frequency (milliseconds)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('USB Scanner')
        self.setGeometry(50, 50, 400, 200)

        self.label = QLabel('Waiting for USB device...')
        self.label.setFont(QFont('Oufit', 16))

        self.scan_button = QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.scan_usb_device)
        self.scan_button.setStyleSheet(
            'QPushButton {background-color: #3498db; color: white; border: 2px solid #2980b9; border-radius: 5px;'
            'padding: 5px; font-size: 18px; font-weight: bold;}'
            'QPushButton:pressed {background-color: white; color: #3498db;}'
            'QPushButton:hover {background-color: white; color: #3498db; border: 2px solid #2980b9;}'
        )
        self.scan_button.setCursor(QCursor(Qt.PointingHandCursor))

        self.dont_scan_button = QPushButton("Don't Scan", self)
        self.dont_scan_button.clicked.connect(self.close_program)
        self.dont_scan_button.setStyleSheet(
            'QPushButton {background-color: #3498db; color: white; border: 2px solid #2980b9; border-radius: 5px;'
            'padding: 5px; font-size: 18px; font-weight: bold;}'
            'QPushButton:pressed {background-color: white; color: #3498db;}'
            'QPushButton:hover {background-color: white; color: #3498db; border: 2px solid #2980b9;}'
        )
        self.dont_scan_button.setCursor(QCursor(Qt.PointingHandCursor))


        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.dont_scan_button)
        self.setLayout(layout)

    def check_usb_devices(self):
        current_devices = {obj.DeviceID: obj.VolumeName for obj in
                           self.wmi_service.query("select * from Win32_LogicalDisk where DriveType = 2")}
        new_devices = {k: v for k, v in current_devices.items() if k not in self.previous_devices}

        if new_devices:
            drive_path, volume_name = list(new_devices.items())[0]
            self.label.setText(f'New USB device connected: {volume_name} ({drive_path})')
            self.show()

        self.previous_devices = current_devices

    def scan_usb_device(self):
        self.label.setText('Scanning files...')
        self.scan_button.setEnabled(False)
        self.dont_scan_button.setEnabled(False)

        drive_path, _ = list(self.previous_devices.items())[0]
        drive_path = drive_path + '\\'

        signatures = {
            ".exe.malware": b"infected code",
            ".dll.trojan": b"hidden payload",
        }

        threat_found = False
        for root, _, files in os.walk(drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    file_data = f.read(1024)
                for signature, pattern in signatures.items():
                    if pattern in file_data:
                        print(f"Potential threat found: {file_path} (matched signature '{signature}')")
                        threat_found = True
                        break
                else:
                    print(f"{file_path} appears safe.")

        if threat_found:
            self.label.setText("Potential threats found. Drive may not be safe.")
        else:
            self.label.setText("Drive is safe.")

        self.scan_button.setEnabled(True)
        self.dont_scan_button.setEnabled(True)
        self.loading_gif.hide()

    def close_program(self):
        self.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = USBScannerGUI()
    sys.exit(app.exec_())
