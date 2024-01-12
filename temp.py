import os
import time
from scapy.all import sniff, wrpcap
import subprocess
import pandas as pd
import numpy as np
import joblib

attacks_f = {
    # "Bot": ["Bwd Pkt Len Mean", "Flow IAT Max", "Flow Duration", "Flow IAT Min", "Label"],
    "DDoS": ["Bwd Pkt Len Std", "Tot Bwd Pkts", "Fwd IAT Tot", "Flow Duration", "Label"],
    "DoS GoldenEye": ["Flow IAT Max", "Bwd Pkt Len Std", "Flow IAT Min", "Tot Bwd Pkts", "Label"],
    "DoS Hulk": ["Bwd Pkt Len Std", "Fwd Pkt Len Std", "Fwd Pkt Len Max", "Flow IAT Min", "Label"],
    # "DoS Slowhttptest": ["Flow IAT Mean", "Fwd Pkt Len Min", "Bwd Pkt Len Mean", "TotLen Bwd Pkts", "Label"],
    # "DoS slowloris": ["Flow IAT Mean", "TotLen Bwd Pkts", "Bwd Pkt Len Mean", "Tot Fwd Pkts", "Label"],
    # "FTP-Patator": ["Fwd Pkt Len Max", "Fwd Pkt Len Std", "Fwd Pkt Len Mean", "Bwd Pkt Len Std", "Label"],
    # "Heartbleed": ["Tot Bwd Pkts", "Fwd Pkt Len Max", "Flow IAT Min", "Bwd Pkt Len Max", "Label"],
    # "Infiltration": ["Fwd Pkt Len Max", "Fwd Pkt Len Mean", "Flow Duration", "TotLen Fwd Pkts", "Label"],
    # "PortScan": ["Flow Byts/s", "TotLen Fwd Pkts", "Fwd IAT Tot", "Flow Duration", "Label"],
    # "SSH-Patator": ["Fwd Pkt Len Max", "Flow Duration", "Flow IAT Max", "TotLen Fwd Pkts", "Label"],
    # "Web Attack": ["Bwd Pkt Len Std", "TotLen Fwd Pkts", "Flow Byts/s", "Flow IAT Max", "Label"]
}
algorithms = ['MLP', 'Random Forest', 'Nearest Neighbors', 'ID3', 'AdaBoost', 'QDA', 'Naive Bayes']

def delete_files(pcap_file_path):
    try:
        os.remove(pcap_file_path)
        print(f"PCAP File deleted: {pcap_file_path}")
    except FileNotFoundError:
        print(f"PCAP File not found: {pcap_file_path}")
    except Exception as e:
        print(f"Error deleting PCAP file: {e}")

    csv_file_path = pcap_file_path + "_Flow.csv"
    try:
        os.remove(csv_file_path)
        print(f"CSV file deleted: {csv_file_path}")
    except FileNotFoundError:
        print(f"CSV file not found: {csv_file_path}")
    except Exception as e:
        print(f"Error deleting CSV file: {e}")

def capture_packets(interface, output_folder, duration):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    timestamp = time.strftime("%Y--%m--%d_%H-%M")
    output_filename = os.path.join(output_folder, f"{timestamp}.pcap")

    try:
        print(f"Capturing packets on interface {interface} for {duration} seconds. Press Ctrl+C to stop.")
        packets = sniff(iface=interface, timeout=duration, store=True, prn=lambda x: x.summary())
        wrpcap(output_filename, packets)
        print("\nPacket capture stopped. Saved to:", output_filename)
        return output_filename  # Return the output filename to then pass to delete files.
    except KeyboardInterrupt:
        print("\nPacket capture stopped. Saved to:", output_filename)
        return None

if __name__ == "__main__":
    interface_to_capture = "Wi-Fi"  # e.g., "eth0" or "wlan0"
    output_folder_path = f"{os.getcwd()}"
    capture_duration = 10  # seconds

    captured_file = capture_packets(interface_to_capture, output_folder_path, capture_duration)

    if captured_file:
        # Changing directory to CICFLowMeter to run the command
        cd_command = f'cd {os.getcwd()}\\bin'
        os.chdir(f'{os.getcwd()}\\bin')

        # Running cfm.abt command
        bat_command = f'cfm.bat "{output_folder_path}" "{output_folder_path}"'
        subprocess.run(bat_command, shell=True)

        # Code for changing csv to 2D array
        # Sending 2D array to ML model
        csv_file = captured_file + "_Flow.csv"
        data=pd.read_csv(csv_file)
        data=data.drop(columns=['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp', 'Label'])
        data.replace([np.inf, -np.inf], 0, inplace=True)
        data=data.fillna(0)
        # model=joblib.load(r"C:\Users\prady\PycharmProjects\python\Project School\CICFlowmeter\model\cic_random_forest_model1.pkl")
        # result=model.predict(data)
        for alg in algorithms:
            print(alg)
            for attack in attacks_f:
                model = joblib.load(f"F:\models\models\\{alg}\\{alg}_{attack}.pkl")
                df1 = data[attacks_f[attack][0:-1]]
                df1 = df1.to_numpy()
                result = model.predict(df1)
                print(attack, result.mean())
                print(result)
                my_list=result.tolist()
                zero_indices = [index+2 for index, value in enumerate(my_list) if value == 0]
                # Print the result
                print("Indices of zeros:", zero_indices)
        # delete_files(captured_file)