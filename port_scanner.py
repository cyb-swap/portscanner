import socket
import argparse
import sys
import threading
from queue import Queue
import random
from scapy.all import IP, TCP, UDP, sr1, sr, ICMP

# Display the banner for the tool
def display_banner():
    banner = """
    =====================================================================================================
    |                                                                                                   |
    |   ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗██████╗ ██╗      ██████╗ ██████╗ ███████╗██████╗      |
    |   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗     |
    |   ██████╔╝██║   ██║██████╔╝   ██║    ╚███╔╝ ██████╔╝██║     ██║   ██║██████╔╝█████╗  ██████╔╝     |
    |   ██╔═══╝ ██║   ██║██╔══██╗   ██║    ██╔██╗ ██╔═══╝ ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██╗     |
    |   ██║     ╚██████╔╝██║  ██║   ██║   ██╔╝ ██╗██║     ███████╗╚██████╔╝██║  ██║███████╗██║  ██║     |
    |   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     |
    |                                                                                                   |
    |                               PortXplorer - Python3                                               |
    |                       Scout Your Network for Open Ports                                           |
    =====================================================================================================
    """
    print(banner)

# Check if a specific port is open on the target host
def check_port(host, port):
    """Check if a port is open on the specified host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Set timeout for connection attempts
            sock.connect((host, port))
        print(f"[+] Port {port} is OPEN (TCP scan)")
    except:
        print(f"[-] Port {port} is CLOSED (TCP scan)")

# Perform a SYN scan on a specific port
def syn_scan(host, port):
    """Perform a SYN scan on a specific port."""
    src_port = random.randint(1024, 65535)  # Choose a random source port
    packet = IP(dst=host)/TCP(sport=src_port, dport=port, flags="S")  # Create SYN packet
    response = sr1(packet, timeout=2, verbose=0)  # Send packet and wait for response

    if response is None:
        print(f"[-] Port {port} is FILTERED (no response)")
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK received
            print(f"[+] Port {port} is OPEN (SYN scan)")
            sr(IP(dst=host)/TCP(sport=src_port, dport=port, flags="R"), timeout=2, verbose=0)  # Send RST to close connection
        elif response[TCP].flags == 0x14:  # RST-ACK received
            print(f"[-] Port {port} is CLOSED (SYN scan)")
    elif response.haslayer(ICMP):
        print(f"[-] Port {port} is FILTERED (ICMP unreachable)")

# Perform a UDP scan on a specific port
def udp_scan(host, port):
    """Perform a UDP scan on a specific port."""
    packet = IP(dst=host)/UDP(dport=port)  # Create UDP packet
    response = sr1(packet, timeout=2, verbose=0)  # Send packet and wait for response

    if response is None:
        print(f"[+] Port {port} is OPEN|FILTERED (UDP scan)")
    elif response.haslayer(UDP):
        print(f"[+] Port {port} is OPEN (UDP scan)")
    elif response.haslayer(ICMP):
        icmp_type = response[ICMP].type
        icmp_code = response[ICMP].code
        if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
            print(f"[-] Port {port} is FILTERED (ICMP unreachable)")
        else:
            print(f"[-] Port {port} is CLOSED (ICMP response)")

# Perform basic OS detection using ICMP and TTL values
def os_detection(host):
    """Perform basic OS detection using TTL values."""
    try:
        packet = IP(dst=host)/ICMP()  # Create ICMP packet
        response = sr1(packet, timeout=2, verbose=0)  # Send packet and wait for response
        if response is not None:
            ttl = response[IP].ttl  # Extract TTL value
            if ttl <= 64:
                print(f"[+] OS Detection: Host {host} is likely a Linux/Unix system (TTL={ttl})")
            elif ttl <= 128:
                print(f"[+] OS Detection: Host {host} is likely a Windows system (TTL={ttl})")
            else:
                print(f"[+] OS Detection: Host {host} has an unusual TTL value (TTL={ttl})")
        else:
            print("[-] OS Detection failed: No response from host.")
    except Exception as e:
        print(f"[-] OS Detection failed: {e}")

# Discover live hosts in a specified subnet
def host_discovery(subnet):
    """Discover live hosts in a subnet."""
    print(f"[+] Discovering hosts in subnet: {subnet}")
    live_hosts = []
    for i in range(1, 255):  # Iterate through possible host addresses
        host = f"{subnet}.{i}"
        packet = IP(dst=host)/ICMP()  # Create ICMP packet
        response = sr1(packet, timeout=1, verbose=0)  # Send packet and wait for response
        if response is not None:
            live_hosts.append(host)
            print(f"[+] Host found: {host}")
    return live_hosts

# Perform threaded port scanning
def threaded_scan(host, ports, scan_type):
    """Perform threaded port scanning."""
    queue = Queue()

    # Worker thread function
    def worker():
        while not queue.empty():
            port = queue.get()
            if scan_type == "tcp":
                check_port(host, port)
            elif scan_type == "syn":
                syn_scan(host, port)
            elif scan_type == "udp":
                udp_scan(host, port)
            queue.task_done()

    # Add ports to the queue
    for port in ports:
        queue.put(port)

    # Create and start threads
    threads = []
    for _ in range(10):  # Adjust thread count as needed
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

# Main function to parse arguments and execute scanning tasks
def main():
    display_banner()

    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner")
    parser.add_argument("-host", type=str, help="Target domain or IP address", required=True)
    parser.add_argument("-p", type=str, help="Port(s) to scan. Use comma-separated list (e.g., 22,80,443) or range (e.g., 1-100)", required=False)
    parser.add_argument("-iL", type=str, help="File containing list of ports to scan", required=False)
    parser.add_argument("-os", action="store_true", help="Perform OS detection")
    parser.add_argument("-subnet", type=str, help="Perform host discovery in a subnet (e.g., 192.168.1)")
    parser.add_argument("-scan", type=str, choices=["tcp", "syn", "udp"], help="Type of scan to perform (tcp, syn, udp)", default="tcp")
    parser.add_argument("-o", type=str, help="Output file to save scan results", required=False)

    args = parser.parse_args()

    # Ensure at least one action is specified
    if not args.p and not args.iL and not args.subnet and not args.os:
        print("[!] Please specify an action to perform (-p, -iL, -subnet, or -os).")
        sys.exit(1)

    host = args.host

    # Handle port scanning
    if args.p:
        if "," in args.p:  # Comma-separated list of ports
            ports = [int(port.strip()) for port in args.p.split(",")]
            threaded_scan(host, ports, args.scan)
        elif "-" in args.p:  # Port range
            try:
                start_port, end_port = map(int, args.p.split("-"))
                ports = range(start_port, end_port + 1)
                threaded_scan(host, ports, args.scan)
            except ValueError:
                print("[!] Invalid port range format. Use start-end, e.g., 20-80.")
        else:  # Single port
            try:
                port = int(args.p)
                if args.scan == "tcp":
                    check_port(host, port)
                elif args.scan == "syn":
                    syn_scan(host, port)
                elif args.scan == "udp":
                    udp_scan(host, port)
            except ValueError:
                print("[!] Invalid port number.")

    # Handle port list file
    if args.iL:
        try:
            with open(args.iL, "r") as file:
                ports = [int(line.strip()) for line in file.readlines()]
                threaded_scan(host, ports, args.scan)
        except FileNotFoundError:
            print(f"[!] File not found: {args.iL}")

    # Perform OS detection
    if args.os:
        os_detection(host)

    # Perform host discovery
    if args.subnet:
        host_discovery(args.subnet)

if __name__ == "__main__":
    main()
