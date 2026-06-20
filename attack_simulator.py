import sys
import os
import time
import socket
import logging

# Suppress Scapy warnings to keep console clean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ANSI colors for premium terminal UI
C_RESET = "\033[0m"
C_GREEN = "\033[32;1m"
C_RED = "\033[31;1m"
C_YELLOW = "\033[33;1m"
C_BLUE = "\033[34;1m"
C_MAGENTA = "\033[35;1m"
C_CYAN = "\033[36;1m"

print(f"{C_BLUE}[SIMULATOR STARTUP] Loading Scapy packet crafting libraries...{C_RESET}")
try:
    from scapy.all import IP, TCP, UDP, Raw, send
except ImportError:
    print(f"{C_RED}[ERROR] Scapy is not installed. Please make sure your venv is active.{C_RESET}")
    sys.exit(1)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def send_benign_traffic(target_ip):
    print(f"\n{C_GREEN}[+] Simulating BENIGN Traffic to {target_ip}...{C_RESET}")
    print("Generating standard bidirectional packet patterns (consistent sizes, standard flags)...")
    
    # Simulate an HTTP request/response exchange
    sport = 49152
    dport = 80
    
    # 1. TCP SYN (Client -> Server)
    syn_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="S", window=64240)
    send(syn_pkt, verbose=0)
    time.sleep(0.1)
    
    # 2. TCP ACK (Client -> Server)
    ack_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="A", window=64240)
    send(ack_pkt, verbose=0)
    time.sleep(0.2)
    
    # 3. HTTP GET (Client -> Server)
    get_payload = "GET /index.html HTTP/1.1\r\nHost: local\r\n\r\n"
    req_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=get_payload)
    send(req_pkt, verbose=0)
    time.sleep(0.5)
    
    # 4. Standard Fin Close
    fin_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="FA")
    send(fin_pkt, verbose=0)
    
    print(f"{C_GREEN}[SUCCESS] Benign traffic simulation complete.{C_RESET}")

def send_portscan(target_ip):
    print(f"\n{C_YELLOW}[+] Simulating RECONNAISSANCE (PortScan) on {target_ip}...{C_RESET}")
    print("Generating rapid outbound TCP SYN scans across multiple ports...")
    
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    # pad with extra ports to create a distinct signature
    ports += list(range(9000, 9030))
    
    sport = 55555
    try:
        for count, port in enumerate(ports):
            # Craft TCP SYN packet
            pkt = IP(dst=target_ip)/TCP(sport=sport, dport=port, flags="S")
            send(pkt, verbose=0)
            if count % 10 == 0:
                print(f"Sent {count} connection probes...")
            time.sleep(0.01) # Rapid transmission
        print(f"{C_YELLOW}[SUCCESS] PortScan simulation complete. Sent {len(ports)} probes.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] PortScan simulation aborted by user.{C_RESET}")

def send_dos_flood(target_ip):
    print(f"\n{C_RED}[+] Simulating Denial of Service (DoS) Flood on {target_ip}...{C_RESET}")
    print("Flooding target with asymmetric, high-frequency UDP packet streams...")
    
    sport = 60000
    dport = 5005
    payload = "X" * 200 # Medium packet size
    
    packet_count = 800
    try:
        for count in range(1, packet_count + 1):
            pkt = IP(dst=target_ip)/UDP(sport=sport, dport=dport)/Raw(load=payload)
            send(pkt, verbose=0)
            if count % 200 == 0:
                print(f"Injected {count} / {packet_count} packets...")
            time.sleep(0.001) # High frequency flood
        print(f"{C_RED}[SUCCESS] DoS Flood simulation complete. Injected {packet_count} packets.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] DoS flood simulation aborted by user.{C_RESET}")

def send_fuzzer(target_ip):
    print(f"\n{C_MAGENTA}[+] Simulating FUZZER Attack on {target_ip}...{C_RESET}")
    print("Generating high-frequency malformed packets with randomized payload sizes...")
    
    sport = 50000
    dport = 80
    import random
    
    packet_count = 500
    try:
        for count in range(1, packet_count + 1):
            # Generate random binary data of variable length (10 to 1000 bytes)
            payload_size = random.randint(10, 1000)
            payload = os.urandom(payload_size)
            
            # Alternate TCP/UDP to simulate complex fuzzing behavior
            proto = random.choice(['TCP', 'UDP'])
            if proto == 'TCP':
                pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=payload)
            else:
                pkt = IP(dst=target_ip)/UDP(sport=sport, dport=dport)/Raw(load=payload)
                
            send(pkt, verbose=0)
            if count % 100 == 0:
                print(f"Sent {count} fuzzed packets...")
            time.sleep(0.002)
        print(f"{C_MAGENTA}[SUCCESS] Fuzzer simulation complete. Sent {packet_count} fuzzed packets.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Fuzzer simulation aborted by user.{C_RESET}")

def send_ssh_patator(target_ip):
    print(f"\n{C_RED}[+] Simulating SSH-Patator (SSH Brute Force) on {target_ip}...{C_RESET}")
    print("Generating rapid connection attempts to port 22 with dummy login payloads...")
    
    sport = 40000
    dport = 22
    
    packet_count = 8
    try:
        for count in range(1, packet_count + 1):
            # Send TCP SYN packet to port 22
            syn_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="S")
            send(syn_pkt, verbose=0)
            time.sleep(0.05)
            
            # Send dummy login payload
            payload = f"SSH-2.0-OpenSSH_8.2\nLogin attempt {count}: user=admin pass=password{count}\n"
            payload_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=payload)
            send(payload_pkt, verbose=0)
            
            print(f"Sent login attempt {count}/{packet_count}...")
            time.sleep(0.4) # Spaced attempts
        print(f"{C_GREEN}[SUCCESS] SSH-Patator simulation complete.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] SSH-Patator simulation aborted by user.{C_RESET}")

def send_ftp_patator(target_ip):
    print(f"\n{C_RED}[+] Simulating FTP-Patator (FTP Brute Force) on {target_ip}...{C_RESET}")
    print("Generating rapid connection attempts to port 21 with dummy login payloads...")
    
    sport = 40001
    dport = 21
    
    packet_count = 8
    try:
        for count in range(1, packet_count + 1):
            # Send TCP SYN packet to port 21
            syn_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="S")
            send(syn_pkt, verbose=0)
            time.sleep(0.05)
            
            # Send dummy login payload
            payload = f"USER admin\r\nPASS password{count}\r\n"
            payload_pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=payload)
            send(payload_pkt, verbose=0)
            
            print(f"Sent FTP login attempt {count}/{packet_count}...")
            time.sleep(0.4) # Spaced attempts
        print(f"{C_GREEN}[SUCCESS] FTP-Patator simulation complete.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] FTP-Patator simulation aborted by user.{C_RESET}")

def get_default_target_ip(local_ip):
    # Defaulting to 1.1.1.1 forces Windows to route traffic externally through the default gateway,
    # which resolves the MAC address instantly and avoids local ARP warning messages/timeouts.
    return '1.1.1.1'

def main():
    default_ip = get_local_ip()
    suggested_target = get_default_target_ip(default_ip)
    
    print(f"{C_CYAN}=====================================================")
    print("       NIDS ATTACK SIMULATOR (EDUCATIONAL DEMO)      ")
    print(f"====================================================={C_RESET}")
    print(f"Detected Local IP: {default_ip}")
    print(f"Suggested Target (to force physical network capture): {suggested_target}")
    
    target_ip = input(f"Enter target IP to inject traffic (Default: {suggested_target}): ").strip()
    if not target_ip:
        target_ip = suggested_target
        
    print(f"\nTargeting interface IP: {C_CYAN}{target_ip}{C_RESET}")
    
    while True:
        print("\nSelect traffic type to simulate:")
        print(f"  1. {C_GREEN}Benign Traffic{C_RESET} (Standard HTTP/TCP connection)")
        print(f"  2. {C_YELLOW}PortScan Attack{C_RESET} (Reconnaissance scan across common ports)")
        print(f"  3. {C_RED}DoS Flood Attack{C_RESET} (Asymmetric flood of packets to a single port)")
        print(f"  4. {C_MAGENTA}Fuzzer Attack{C_RESET} (Malformed packets with randomized sizes)")
        print(f"  5. {C_RED}SSH-Patator Attack{C_RESET} (SSH Brute Force login attempts)")
        print(f"  6. {C_RED}FTP-Patator Attack{C_RESET} (FTP Brute Force login attempts)")
        print("  7. Exit")
        
        choice = input("Enter choice (1-7): ").strip()
        if choice == '1':
            send_benign_traffic(target_ip)
        elif choice == '2':
            send_portscan(target_ip)
        elif choice == '3':
            send_dos_flood(target_ip)
        elif choice == '4':
            send_fuzzer(target_ip)
        elif choice == '5':
            send_ssh_patator(target_ip)
        elif choice == '6':
            send_ftp_patator(target_ip)
        elif choice == '7':
            print("Exiting simulator. Goodbye!")
            break
        else:
            print("Invalid choice, try again.")
            
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nSimulator interrupted. Exiting.")
