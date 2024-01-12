import sys
import os
import time
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QAction, QLabel, QPushButton
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from scapy.all import sniff, wrpcap
import pandas as pd
import joblib
import numpy as np

pcap_file_directory = f"{os.getcwd()}\\output\\pcap"
network_results = "something might be wrong"
attacks_f = {
    "Bot": ["Bwd Pkt Len Mean", "Flow IAT Max", "Flow Duration", "Flow IAT Min", "Label"],
    "DDoS": ["Bwd Pkt Len Std", "Tot Bwd Pkts", "Fwd IAT Tot", "Flow Duration", "Label"],
    "DoS GoldenEye": ["Flow IAT Max", "Bwd Pkt Len Std", "Flow IAT Min", "Tot Bwd Pkts", "Label"],
    "DoS Hulk": ["Bwd Pkt Len Std", "Fwd Pkt Len Std", "Fwd Pkt Len Max", "Flow IAT Min", "Label"],
    "DoS Slowhttptest": ["Flow IAT Mean", "Fwd Pkt Len Min", "Bwd Pkt Len Mean", "TotLen Bwd Pkts", "Label"],
    "DoS slowloris": ["Flow IAT Mean", "TotLen Bwd Pkts", "Bwd Pkt Len Mean", "Tot Fwd Pkts", "Label"],
    "FTP-Patator": ["Fwd Pkt Len Max", "Fwd Pkt Len Std", "Fwd Pkt Len Mean", "Bwd Pkt Len Std", "Label"],
    "Heartbleed": ["Tot Bwd Pkts", "Fwd Pkt Len Max", "Flow IAT Min", "Bwd Pkt Len Max", "Label"],
    "Infiltration": ["Fwd Pkt Len Max", "Fwd Pkt Len Mean", "Flow Duration", "TotLen Fwd Pkts", "Label"],
    "PortScan": ["Flow Byts/s", "TotLen Fwd Pkts", "Fwd IAT Tot", "Flow Duration", "Label"],
    "SSH-Patator": ["Fwd Pkt Len Max", "Flow Duration", "Flow IAT Max", "TotLen Fwd Pkts", "Label"],
    "Web Attack": ["Bwd Pkt Len Std", "TotLen Fwd Pkts", "Flow Byts/s", "Flow IAT Max", "Label"]
}
algorithms = ['Random Forest']


# algorithms = ['AdaBoost', 'ID3', 'MLP', 'Naive Bayes', 'Nearest Neighbors', 'QDA', 'Random Forest']


class MalwareDetectionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Detection App")
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.analysis_thread = AnalysisThread(self)
        self.analysis_thread.finished.connect(self.show_network_result)
        self.create_menu()
        self.setStyleSheet(
            "QMainWindow { background-color: #f0f0f0; }"
            "QMenuBar { background-color: #333; color: #fff; }"
            "QMenuBar::item { background-color: #333; padding: 8px 16px; }"
            "QMenuBar::item:selected { background-color: #555; }"
            "QLabel { font-size: 16px; padding: 20px; }"
            "QPushButton { font-size: 14px; padding: 8px; }"
        )
        self.show_initial_content()

    def create_menu(self):
        menubar = self.menuBar()
        menu = menubar.addMenu('Menu')
        actions = [
            ('Home', self.show_initial_content),
            ('Network Analysis', self.show_network_content),
            ('System Analysis', self.show_system_content),
            ('Document Analysis', self.show_document_content)
        ]
        for action_text, callback in actions:
            menu_action = QAction(action_text, self)
            menu_action.triggered.connect(callback)
            menu.addAction(menu_action)

    def clear_layout(self):
        for i in reversed(range(self.main_layout.count())):
            widget = self.main_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def show_initial_content(self):
        self.clear_layout()
        label = QLabel("Welcome to the Malware detection app from G91", self)
        self.main_layout.addWidget(label, alignment=Qt.AlignCenter)

    def show_network_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Network Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Start", self)
        option_button.clicked.connect(self.start_network_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_system_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start System Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Start", self)
        option_button.clicked.connect(self.start_system_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_document_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Document Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Select file", self)
        option_button.clicked.connect(self.start_document_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def start_network_analysis(self):
        self.clear_layout()
        option_label = QLabel("Processing your network", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        self.analysis_thread.start()

    def start_document_analysis(self):
        self.clear_layout()
        option_label = QLabel("Clicked on start Document Analysis button", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def start_system_analysis(self):
        self.clear_layout()
        option_label = QLabel("Clicked on start System Analysis button", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def show_network_result(self):
        self.clear_layout()
        global network_results
        option_label = QLabel(network_results, self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)


class AnalysisThread(QThread):
    finished = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)

    def run(self):
        global network_results
        network_results = loop_comp("Wi-Fi", 30)
        self.finished.emit()


def delete_file(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting file {file_path}: {e}")


def capture_packets(interface, output_folder, duration):
    timestamp = time.strftime("%Y--%m--%d_%H-%M")
    pcap_file_path = os.path.join(output_folder, f"{timestamp}.pcap")
    try:
        packets = sniff(iface=interface, timeout=duration, store=True)
        wrpcap(pcap_file_path, packets)
        return pcap_file_path
    except KeyboardInterrupt:
        return None


def run_flow_analysis():
    cd_command = pcap_file_directory[:-11] + "\\bin"
    os.chdir(cd_command)
    bat_command = f'cfm.bat "{pcap_file_directory}" "{pcap_file_directory[:-4]}\\csv"'
    try:
        subprocess.run(bat_command, shell=True, check=True)
    except subprocess.CalledProcessError:
        pass


def process_csv_file(csv_file_path):
    try:
        df = pd.read_csv(csv_file_path)
        df.replace([np.inf, -np.inf], 0, inplace=True)
        df.fillna(0, inplace=True)
        results = {}
        for alg in algorithms:
            for attack in attacks_f:
                model = joblib.load(pcap_file_directory[:-11] + f"models\{alg}\{alg}_{attack}.pkl")
                df1 = df[attacks_f[attack][0:-1]]
                df1 = df1.to_numpy()
                t_output = model.predict_proba(df1)
                t_output = t_output[:, 0] * 100
                output = 0
                for i in t_output:
                    if i > 90:
                        output = 1
                results[attack] = output
        delete_file(csv_file_path)
        for key, var in results.items():
            if var != 0:
                return key
        return "Detected Safe"
    except Exception as e:
        print(f"Error: {str(e)}")
        delete_file(csv_file_path)
        return "Error Happened"


def loop_comp(interface, capture_duration1):
    pcap_file_path = capture_packets(interface, pcap_file_directory, capture_duration1)
    if pcap_file_path is not None:
        run_flow_analysis()
        if pcap_file_directory is not None:
            label = process_csv_file(pcap_file_directory[:-4] + "csv" + pcap_file_path[-32 + 8:-4] + "pcap_Flow.csv")
            delete_file(pcap_file_path)
            return label


def main():
    app = QApplication(sys.argv)
    window = MalwareDetectionApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
