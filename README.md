# 🛡️ Live Hybrid Machine Learning NIDS (Network Intrusion Detection System)

This project is an advanced, educational **Hybrid Machine Learning Network Intrusion Detection System (NIDS)**. It merges real-time packet capture, complex network feature engineering, and dual machine learning models to detect web attacks, denial of service, scans, and brute-force attempts live on your network.

---

## 🚀 Key Features

* **Dual-Model ML Classifier**:
  * **UNSW-NB15 Model**: Classified using a 39-feature Random Forest model to detect general attacks (`DoS`, `Exploits`, `Fuzzers`, `Reconnaissance`, etc.).
  * **CICIDS-2017 Model**: Classified using a 78-feature specialized Random Forest model to identify brute-force logins (`SSH-Patator` and `FTP-Patator`).
* **Real-time Feature Extractor**: Reconstructs multi-stage flow metrics (durations, packet sizes, window flags, standard deviations, and throughputs) dynamically from physical network traffic.
* **Interactive Attack Simulator**: A built-in traffic injection tool allowing you to test the NIDS live with 6 different traffic profiles:
  1. `Benign` HTTP requests.
  2. `PortScan` reconnaissance scans.
  3. `DoS Flood` UDP flooding.
  4. `Fuzzers` payload injections.
  5. `SSH-Patator` brute force.
  6. `FTP-Patator` brute force.
* **ANSI Color-Coded Dashboard**: Clean, real-time logging console designed for high-impact educational demos.

---

## 📂 Project Architecture & Codebase

```text
├── nids_sniffer.py          # Primary packet capture and multi-model inference engine (Run as Admin)
├── attack_simulator.py      # Educational packet injection CLI tool
├── nids_model.joblib        # Compiled UNSW-NB15 Random Forest weights
├── cicids_model.joblib      # Compiled CICIDS-2017 Random Forest weights
├── requirements.txt         # Project package dependencies
└── README.md                # Documentation
```

---

## 🛠️ Installation & Setup

### Prerequisites
* **Python 3.10+**
* **Npcap / WinPcap** (Required for Scapy to capture physical interface traffic on Windows. Download and install Npcap in WinPcap compatibility mode).

### Step 1: Clone and Activate Virtual Environment
```powershell
# Create a virtual environment
python -m venv venv
# Activate virtual environment
venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 💻 How to Run the Demo

### 1. Start the Live NIDS Sniffer (requires Administrator privileges)
Open an **Administrator command prompt/PowerShell** in the project directory, activate the venv, and run:
```powershell
venv\Scripts\python -u nids_sniffer.py
```
*The console will print diagnostic details confirming both the UNSW and CICIDS models are loaded and active.*

### 2. Launch the Attack Simulator
In a separate standard terminal window, run:
```powershell
venv\Scripts\python attack_simulator.py
```

### 3. Simulate Attacks
1. Enter your target IP (press `Enter` to use default `1.1.1.1` to force physical network gateway routing).
2. Choose any attack (e.g., `5` for SSH Brute Force or `6` for FTP Brute Force).
3. Switch back to your Sniffer window to observe the live machine learning classifications and confidence scores!

---

## 🧠 Educational Concepts Covered

1. **Flow Reconstruction**: Network cards capture packet fragments. A NIDS groups them by TCP/UDP 5-tuple (`Src IP`, `Dst IP`, `Src Port`, `Dst Port`, `Protocol`) into directional flows.
2. **Feature Engineering**: Bridging the gap between raw bytes and model inputs by calculating statistical features (standard deviation of packet size, flow duration in microseconds, and TCP window flags).
3. **Multi-Model Inference**: Routing flow queries to specialized classifiers based on connection patterns, illustrating how microservices handle hybrid security environments.
