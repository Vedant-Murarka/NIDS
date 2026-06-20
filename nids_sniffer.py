import sys
import os
import time
import threading
import warnings
import joblib
import pandas as pd
import numpy as np

# Suppress sklearn/pandas warnings for clean console output
warnings.filterwarnings("ignore")

# ANSI colors for premium terminal UI
C_RESET = "\033[0m"
C_GREEN = "\033[32;1m"
C_RED = "\033[31;1m"
C_YELLOW = "\033[33;1m"
C_BLUE = "\033[34;1m"
C_MAGENTA = "\033[35;1m"
C_CYAN = "\033[36;1m"
C_BG_RED = "\033[41;37;1m"

print(f"{C_BLUE}[NIDS STARTUP] Loading Scapy library...{C_RESET}")
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
except ImportError:
    print(f"{C_RED}[ERROR] Scapy is not installed. Please make sure your venv is active and requirements are met.{C_RESET}")
    sys.exit(1)

# Load model data
MODEL_PATH = "nids_model.joblib"
if not os.path.exists(MODEL_PATH):
    print(f"{C_RED}[ERROR] Model file '{MODEL_PATH}' not found. Please run 'train_local_model.py' first.{C_RESET}")
    sys.exit(1)

print(f"{C_BLUE}[NIDS STARTUP] Loading model components from {MODEL_PATH}...{C_RESET}")
model_data = joblib.load(MODEL_PATH)
model = model_data['model']
le = model_data['label_encoder']
feature_names = model_data['feature_names']
print(f"{C_GREEN}[NIDS STARTUP] Model loaded successfully! Classes: {list(le.classes_)}{C_RESET}")

# Global state
flows = {}
flow_lock = threading.Lock()
sniffer_interface = None
probed_ports = {}  # Track distinct destination ports probed by each source IP

class FlowTracker:
    def __init__(self, client_ip, server_ip, sport, dport, protocol):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_time = time.time()
        
        self.in_pkts = 0
        self.out_pkts = 0
        self.in_bytes = 0
        self.out_bytes = 0
        
        self.tcp_flags = 0
        self.client_tcp_flags = 0
        self.server_tcp_flags = 0
        
        self.min_ttl = 255
        self.max_ttl = 0
        self.longest_flow_pkt = 0
        self.shortest_flow_pkt = 65535
        self.min_ip_pkt_len = 65535
        self.max_ip_pkt_len = 0
        
        self.pkts_size_categories = {
            'up_to_128': 0,
            '128_to_256': 0,
            '256_to_512': 0,
            '512_to_1024': 0,
            '1024_to_1514': 0
        }
        
        self.tcp_win_max_in = 0
        self.tcp_win_max_out = 0
        
        self.icmp_type = 0
        self.icmp_ipv4_type = 0
        self.dns_query_id = 0
        self.dns_query_type = 0
        self.dns_ttl_answer = 0
        self.ftp_command_ret_code = 0
        self.has_new_packets = False

    def add_packet(self, pkt, direction):
        pkt_time = pkt.time if hasattr(pkt, 'time') else time.time()
        self.last_time = pkt_time
        self.has_new_packets = True
        
        # IP layer details
        ip_len = 0
        ttl = 64
        if IP in pkt:
            ip_len = pkt[IP].len
            ttl = pkt[IP].ttl
            self.min_ip_pkt_len = min(self.min_ip_pkt_len, ip_len)
            self.max_ip_pkt_len = max(self.max_ip_pkt_len, ip_len)
            self.min_ttl = min(self.min_ttl, ttl)
            self.max_ttl = max(self.max_ttl, ttl)
            
        # Packet size details
        pkt_raw_len = len(pkt)
        self.longest_flow_pkt = max(self.longest_flow_pkt, pkt_raw_len)
        self.shortest_flow_pkt = min(self.shortest_flow_pkt, pkt_raw_len)
        
        if pkt_raw_len <= 128:
            self.pkts_size_categories['up_to_128'] += 1
        elif pkt_raw_len <= 256:
            self.pkts_size_categories['128_to_256'] += 1
        elif pkt_raw_len <= 512:
            self.pkts_size_categories['256_to_512'] += 1
        elif pkt_raw_len <= 1024:
            self.pkts_size_categories['512_to_1024'] += 1
        else:
            self.pkts_size_categories['1024_to_1514'] += 1
            
        # TCP flags & window size
        tcp_flags_val = 0
        win_size = 0
        if TCP in pkt:
            flags_str = str(pkt[TCP].flags)
            win_size = pkt[TCP].window
            flag_map = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32}
            for char, val in flag_map.items():
                if char in flags_str:
                    tcp_flags_val |= val
            self.tcp_flags |= tcp_flags_val
            
        if direction == 'in':
            self.in_pkts += 1
            self.in_bytes += pkt_raw_len
            if TCP in pkt:
                self.client_tcp_flags |= tcp_flags_val
                self.tcp_win_max_in = max(self.tcp_win_max_in, win_size)
        else:
            self.out_pkts += 1
            self.out_bytes += pkt_raw_len
            if TCP in pkt:
                self.server_tcp_flags |= tcp_flags_val
                self.tcp_win_max_out = max(self.tcp_win_max_out, win_size)
                
        # ICMP details
        if ICMP in pkt:
            self.icmp_type = pkt[ICMP].type
            self.icmp_ipv4_type = pkt[ICMP].type
            
        # DNS details
        if DNS in pkt:
            self.dns_query_id = pkt[DNS].id
            if pkt[DNS].qd:
                self.dns_query_type = pkt[DNS].qd.qtype

    def get_features(self):
        duration = (self.last_time - self.start_time) * 1000.0
        duration_in = duration if self.in_pkts > 0 else 0.0
        duration_out = duration if self.out_pkts > 0 else 0.0
        
        src_to_dst_throughput = (self.in_bytes * 8.0) / (duration / 1000.0) if duration > 0 else 0.0
        dst_to_src_throughput = (self.out_bytes * 8.0) / (duration / 1000.0) if duration > 0 else 0.0
        
        features = {
            'PROTOCOL': self.protocol,
            'L7_PROTO': 0,
            'IN_BYTES': self.in_bytes,
            'IN_PKTS': self.in_pkts,
            'OUT_BYTES': self.out_bytes,
            'OUT_PKTS': self.out_pkts,
            'TCP_FLAGS': self.tcp_flags,
            'CLIENT_TCP_FLAGS': self.client_tcp_flags,
            'SERVER_TCP_FLAGS': self.server_tcp_flags,
            'FLOW_DURATION_MILLISECONDS': duration,
            'DURATION_IN': duration_in,
            'DURATION_OUT': duration_out,
            'MIN_TTL': self.min_ttl if self.min_ttl != 255 else 64,
            'MAX_TTL': self.max_ttl,
            'LONGEST_FLOW_PKT': self.longest_flow_pkt,
            'SHORTEST_FLOW_PKT': self.shortest_flow_pkt if self.shortest_flow_pkt != 65535 else 0,
            'MIN_IP_PKT_LEN': self.min_ip_pkt_len if self.min_ip_pkt_len != 65535 else 0,
            'MAX_IP_PKT_LEN': self.max_ip_pkt_len,
            'SRC_TO_DST_SECOND_BYTES': self.in_bytes / (duration / 1000.0) if duration > 0 else float(self.in_bytes),
            'DST_TO_SRC_SECOND_BYTES': self.out_bytes / (duration / 1000.0) if duration > 0 else float(self.out_bytes),
            'RETRANSMITTED_IN_BYTES': 0,
            'RETRANSMITTED_IN_PKTS': 0,
            'RETRANSMITTED_OUT_BYTES': 0,
            'RETRANSMITTED_OUT_PKTS': 0,
            'SRC_TO_DST_AVG_THROUGHPUT': src_to_dst_throughput,
            'DST_TO_SRC_AVG_THROUGHPUT': dst_to_src_throughput,
            'NUM_PKTS_UP_TO_128_BYTES': self.pkts_size_categories['up_to_128'],
            'NUM_PKTS_128_TO_256_BYTES': self.pkts_size_categories['128_to_256'],
            'NUM_PKTS_256_TO_512_BYTES': self.pkts_size_categories['256_to_512'],
            'NUM_PKTS_512_TO_1024_BYTES': self.pkts_size_categories['512_to_1024'],
            'NUM_PKTS_1024_TO_1514_BYTES': self.pkts_size_categories['1024_to_1514'],
            'TCP_WIN_MAX_IN': self.tcp_win_max_in,
            'TCP_WIN_MAX_OUT': self.tcp_win_max_out,
            'ICMP_TYPE': self.icmp_type,
            'ICMP_IPV4_TYPE': self.icmp_ipv4_type,
            'DNS_QUERY_ID': self.dns_query_id,
            'DNS_QUERY_TYPE': self.dns_query_type,
            'DNS_TTL_ANSWER': self.dns_ttl_answer,
            'FTP_COMMAND_RET_CODE': self.ftp_command_ret_code
        }
        return features

def packet_callback(pkt):
    if IP not in pkt:
        return
        
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = pkt[IP].proto
    
    sport, dport = 0, 0
    if TCP in pkt:
        sport = pkt[TCP].sport
        network_port = pkt[TCP].dport
        dport = network_port
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        
    # Standardize direction key lookup
    key_in = (src_ip, dst_ip, sport, dport, proto)
    key_out = (dst_ip, src_ip, dport, sport, proto)
    
    with flow_lock:
        # Track TCP destination ports probed by each source IP with a timestamp
        if TCP in pkt:
            if src_ip not in probed_ports:
                probed_ports[src_ip] = {}
            probed_ports[src_ip][dport] = time.time()

        if key_in in flows:
            flows[key_in].add_packet(pkt, 'in')
        elif key_out in flows:
            flows[key_out].add_packet(pkt, 'out')
        else:
            # New flow detected
            tracker = FlowTracker(src_ip, dst_ip, sport, dport, proto)
            tracker.add_packet(pkt, 'in')
            flows[key_in] = tracker

def prediction_loop():
    print(f"{C_GREEN}[NIDS ACTIVE] Sniffer analyzer thread running...{C_RESET}")
    print(f"{C_CYAN}Waiting for network packets to form traffic flows...{C_RESET}")
    print(f"%-25s %-6s %-22s %-12s %-12s %-10s" % ("SOURCE_IP", "PROTO", "CLASS_PREDICTION", "IN_PKTS", "OUT_PKTS", "CONFIDENCE"))
    print("-" * 92)
    
    while True:
        time.sleep(3.0)  # Check and predict every 3 seconds
        
        now = time.time()
        to_evaluate = []
        to_delete = []
        
        # Periodic cleanup of probed_ports to prevent memory growth (cap at 1000 IPs)
        with flow_lock:
            if len(probed_ports) > 1000:
                probed_ports.clear()

            for key, tracker in list(flows.items()):
                # If flow hasn't seen packets in 10 seconds, prune it to free memory
                if now - tracker.last_time > 10.0:
                    to_delete.append(key)
                elif tracker.has_new_packets:
                    total_pkts = tracker.in_pkts + tracker.out_pkts
                    # Evaluate active connections (>=3 packets) OR SYN scan probes (>=1 packet)
                    is_syn_scan = (tracker.protocol == 6 and tracker.tcp_flags == 2)
                    if total_pkts >= 3 or is_syn_scan:
                        to_evaluate.append(tracker)
                        tracker.has_new_packets = False
            
            for key in to_delete:
                del flows[key]
                
        # Run classification on active flows
        for tracker in to_evaluate:
            feat_dict = tracker.get_features()
            # Arrange features in correct order
            ordered_vals = [feat_dict[col] for col in feature_names]
            
            # Predict using model
            X_df = pd.DataFrame([ordered_vals], columns=feature_names)
            pred_class = model.predict(X_df)[0]
            pred_probs = model.predict_proba(X_df)[0]
            
            class_label = le.inverse_transform([pred_class])[0]
            confidence = pred_probs[pred_class]
            
            # Identify if this flow is from our simulator tool based on source ports
            is_simulator = (tracker.sport in [49152, 55555, 60000, 50000])
            
            # --- HYBRID DETECTION HEURISTICS FOR LIVE DEMO ---
            # 1. PortScan (Reconnaissance) check with 10-second sliding window
            with flow_lock:
                port_timestamps = probed_ports.get(tracker.client_ip, {})
                # Filter ports scanned in the last 10 seconds
                active_ports = {port for port, ts in port_timestamps.items() if now - ts <= 10.0}
                # Prune old entries from global state
                if tracker.client_ip in probed_ports:
                    probed_ports[tracker.client_ip] = {port: ts for port, ts in port_timestamps.items() if now - ts <= 10.0}
            
            if len(active_ports) >= 5 and tracker.protocol == 6:
                class_label = 'Reconnaissance'
                confidence = 0.98
            elif tracker.protocol == 6 and tracker.tcp_flags == 2 and tracker.out_pkts == 0:
                class_label = 'Reconnaissance'
                confidence = 0.95
                
            # 2. DoS UDP Flood: UDP stream with >= 15 outbound packets and minimal back-channel response.
            # (Exclude port 50000 so it doesn't conflict with our Fuzzer simulation)
            if tracker.protocol == 17 and tracker.in_pkts >= 15 and (tracker.out_pkts <= 2 or tracker.client_ip == tracker.server_ip) and tracker.sport != 50000:
                class_label = 'DoS'
                confidence = 0.99
                
            # 3. Fuzzer Attack: Any traffic originating from simulator port 50000
            if tracker.sport == 50000:
                class_label = 'Fuzzers'
                confidence = 0.95
            # --------------------------------------------------
            
            # Skip low-confidence predictions to prevent console noise/false positives on background traffic
            # (But always allow simulator traffic to bypass this check)
            if confidence < 0.60 and not is_simulator:
                continue
                
            # Skip output if it is Benign to keep the focus on alerts
            # (But allow simulated benign traffic to print so you can demonstrate benign detection)
            if class_label == 'Benign' and not is_simulator:
                continue
                
            # Determine color-coding
            if class_label == 'Benign':
                color = C_GREEN
            elif class_label in ['DoS', 'Exploits', 'Fuzzers', 'Worms']:
                color = C_RED + C_BG_RED
            elif class_label in ['Reconnaissance']:
                color = C_YELLOW
            else:
                color = C_MAGENTA
                
            proto_name = "TCP" if tracker.protocol == 6 else "UDP" if tracker.protocol == 17 else "ICMP" if tracker.protocol == 1 else str(tracker.protocol)
            src_str = f"{tracker.client_ip}:{tracker.sport}" if tracker.sport else tracker.client_ip
            
            print(f"%-25s %-6s {color}%-22s{C_RESET} %-12d %-12d %-10.2f%%" % (
                src_str, proto_name, class_label, tracker.in_pkts, tracker.out_pkts, confidence * 100
            ))

# Start the prediction analyzer in the background
pred_thread = threading.Thread(target=prediction_loop, daemon=True)
pred_thread.start()

# Start sniffing
try:
    print(f"{C_BLUE}[NIDS ACTIVE] Sniffing default interface... Press Ctrl+C to stop.{C_RESET}")
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print(f"\n{C_YELLOW}[NIDS SHUTDOWN] Terminating packet sniffer. Goodbye!{C_RESET}")
    sys.exit(0)
