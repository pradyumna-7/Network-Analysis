import sys
import os
import time
import json
import subprocess
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QAction, QLabel, QPushButton
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from scapy.all import sniff, wrpcap
import requests
import pandas as pd
from PyQt5.QtWidgets import QSizePolicy
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib

matplotlib.use('Qt5Agg')

pcap_file_directory = f"{os.getcwd()}\\output\\pcap"
network_results = [[]]
text = ""


class AnalysisThread(QThread):
    finished = pyqtSignal(list)

    def __init__(self, parent):
        super().__init__(parent)

    def run(self):
        global network_results
        network_results = loop_comp("Wi-Fi", 10)
        self.finished.emit(network_results)


class MalwareDetectionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)  # Set central widget
        self.main_layout = QVBoxLayout(self.central_widget)  # Create main layout
        self.analysis_thread = AnalysisThread(self)
        self.analysis_thread.finished.connect(self.update_network_result)
        self.setWindowTitle("Malware Detection App")

        # Set the style sheet for the menu bar
        self.menuBar().setStyleSheet("""
                QMenuBar{
                    color:white;
                    background-color:#1f184d;
                } """)

        self.setStyleSheet("background-color:#0d0926;")
        self.create_menu()
        self.show_initial_content()

    def create_menu(self):
        menubar = self.menuBar()
        menu = menubar.addMenu('Menu')
        menu.setStyleSheet("color:red;")
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

    def update_network_result(self, network_results):
        self.timer.stop()
        self.show_network_result(network_results)

    def clear_layout(self):
        for i in reversed(range(self.main_layout.count())):
            widget = self.main_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def show_initial_content(self):
        self.clear_layout()
        # Add logo to top left corner
        logo_label = QLabel(self)
        logo_pixmap = QPixmap("logo.png")
        logo_label.setPixmap(logo_pixmap)
        scaled_pixmap = logo_pixmap.scaled(300, 300, Qt.KeepAspectRatio)
        logo_label.setPixmap(scaled_pixmap)
        logo_label.setAlignment(Qt.AlignLeft)
        self.main_layout.addWidget(logo_label)

        # Add text header
        header_label = QLabel("Network Scanner", self)
        header_label.setFont(QFont("Outfit", 16, weight=QFont.Bold))  # Set font to Outfit and bold
        header_label.setStyleSheet("color:white;")
        self.main_layout.addWidget(header_label)

        # Add paragraph text
        paragraph_label = QLabel("In today's dynamic network security landscape, the demand for efficient and dependable\n"
                                 " network scanning solutions has reached unprecedented levels. Organizations of all sizes\n"
                                 " seek tools that can rapidly identify vulnerabilities, fortify network defenses, and produce\n"
                                 " thorough reports, all within budgetary constraints. Addressing this imperative, we offer \n"
                                 "state-of-the-art network scanning solutions engineered for unmatched speed, \n"
                                 "security, and affordability.\n\n\n", self)
        paragraph_label.setFont(QFont("Roboto", 11))  # Set font to Outfit
        paragraph_label.setStyleSheet("color:white;")
        self.main_layout.addWidget(paragraph_label)

        hover_label = QLabel("Hover over to the menu to see more!", self)
        hover_label.setFont(QFont("Bahnschrift", 16))
        hover_label.setStyleSheet("color:white;")
        self.main_layout.addWidget(hover_label)

        # Add another image to the right of the text
        img_label = QLabel(self)
        img_pixmap = QPixmap("img1-1@2x.png")
        img_label.setPixmap(img_pixmap)
        scaled_pixmap = img_pixmap.scaled(500, 500, Qt.KeepAspectRatio)
        img_label.setPixmap(scaled_pixmap)
        img_label.setAlignment(Qt.AlignLeft)
        self.main_layout.addWidget(img_label)

    def show_network_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Network Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_label.setStyleSheet("color:white;")
        option_label.setFont(QFont("Outfit", 16))
        option_button = QPushButton("Start", self)
        option_button.setFont(QFont("Outfit", 12))
        option_button.setStyleSheet(
            """
            QPushButton {
                background-color: #007BFF; /* Blue background color */
                color: white; /* White text color */
                border-radius: 10px; /* Rounded corners */
                padding: 10px 20px; /* Larger padding */
                border: 2px solid #007BFF; /* Blue border */
            }
            QPushButton:hover {
                background-color: #0056b3; /* Darker blue on hover */
            }
            """
        )
        option_button.clicked.connect(self.start_network_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_system_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start System Analysis", self)
        option_label.setStyleSheet("color:white;")
        option_label.setFont(QFont("Outfit", 16))
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Start", self)
        option_button.clicked.connect(self.start_system_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_document_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Document Analysis", self)
        option_label.setStyleSheet("color:white;")
        option_label.setFont(QFont("Outfit", 16))
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Select file", self)
        option_button.clicked.connect(self.start_document_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def update_dots(self):
        if self.dots_index == 0:
            self.option_label.setText("Processing your network")
        elif self.dots_index == 1:
            self.option_label.setText("Processing your network.")
        elif self.dots_index == 2:
            self.option_label.setText("Processing your network..")
        else:
            self.option_label.setText("Processing your network...")
            self.dots_index = 0
        self.dots_index += 1

    def start_network_analysis(self):
        self.clear_layout()
        self.option_label = QLabel("Processing your network", self)
        self.main_layout.addWidget(self.option_label, alignment=Qt.AlignCenter)
        self.option_label.setStyleSheet("color:white;")
        self.option_label.setFont(QFont("Outfit", 16))

        self.dots_index = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_dots)
        self.timer.start(500)

        self.analysis_thread.start()

    def start_document_analysis(self):
        self.clear_layout()
        option_label = QLabel("No function has been assigned here, this will be a future goal.", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def start_system_analysis(self):
        self.clear_layout()
        option_label = QLabel("No function has been assigned here, this will be a future goal.", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def show_network_result(self, network_results):
        global text
        self.clear_layout()
        data = network_results[:-1]
        print("Hi...", data)
        if data:
            plt.rcParams['font.family'] = 'sans-serif'
            text += "\nNote: The accuracy of the table may not be perfect due to the constraint of open source data."
            fig, ax = plt.subplots()
            result_dict = {}

            for key, value in data:
                if len(value) < 3:
                    # If the length is less than 3, adding zeros to make it 3 elements
                    value.extend([0.0] * (3 - len(value)))
                result_dict[key.strip('.')] = value

            x_labels = list(result_dict.keys())  # X-axis labels
            percentages = list(result_dict.values())  # List of lists containing percentages

            bar_width = 0.25

            index = np.arange(len(x_labels))
            labels = ['AdaBoost', 'Nearest Neighbors', 'Random Forest']

            for i in range(3):
                ax.bar(index + i * bar_width, [percentage[i] for percentage in percentages], bar_width, label=labels[i])

            for i in range(3):
                for j, val in enumerate([percentage[i] for percentage in percentages]):
                    ax.text(index[j] + i * bar_width, val + 1, f'{round(val)}', ha='center')

            ax.set_xlabel('Attack Types', fontsize='xx-large')
            ax.set_ylabel('% of Chance', fontsize='xx-large')
            ax.set_title('Malware Detection Results', fontsize='xx-large')
            ax.set_xticks(index + bar_width, x_labels, fontsize='medium')
            #             ax.set_xticklabels(attack_types)
            ax.legend(title='Classification Algorithms', fontsize='large', title_fontsize='x-large')
            ax.set_ylim(0, 100)
            plt.yticks(fontsize='large')
            border_box = dict(facecolor='none', edgecolor='black', linewidth=0.5)
            ax.annotate(text,
                        xy=(0.5, 0.98),
                        xycoords='axes fraction',
                        ha='center',
                        va='top',
                        fontsize='medium',
                        bbox=border_box)
            # Create the FigureCanvas after the figure is properly defined
            canvas = FigureCanvas(fig)
            self.main_layout.addWidget(canvas)
            canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.showMaximized()
        else:
            option_label = QLabel("Something went wrong or your network did not contain any packets or data.", self)
            self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)


def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"Deleted file:{file_path}")
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
    global text
    try:
        print("here")
        api_url = 'https://malwaredetection.onrender.com'
        print("Reading CSV file...")
        df = pd.read_csv(csv_file_path)
        print("CSV file read successfully.")
        delete_file(csv_file_path)
        df.to_json("dummy.json")
        with open('dummy.json') as f:
            data = json.load(f)
        delete_file("dummy.json")
        data_to_send = data
        response = requests.post(api_url, json=data_to_send)
        if response.status_code == 200:
            api_response = response.json()
            attack_data = {}
            text = api_response[-1]
            for item in api_response:
                attack_type = item[2][11:]
                if attack_type in attack_data:
                    attack_data[attack_type].append(item[1])
                else:
                    attack_data[attack_type] = [item[1]]
            return list(attack_data.items())
        else:
            print("Error:", response.status_code, response.text)
        return [["Our api is currently not responding pls try again later"]]

    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return [["Error processing CSV file"]]


def loop_comp(interface, capture_duration1):
    pcap_file_path = capture_packets(interface, pcap_file_directory, capture_duration1)
    if pcap_file_path is not None:
        run_flow_analysis()
        if pcap_file_directory is not None:
            label = process_csv_file(pcap_file_directory[:-4] + "csv" + pcap_file_path[-32 + 8:-4] + "pcap_Flow.csv")
            print(label)
            delete_file(pcap_file_path)
            return label


def main():
    app = QApplication(sys.argv)
    window = MalwareDetectionApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
