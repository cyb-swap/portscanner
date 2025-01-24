# Advanced Python Port Scanner

## Overview

The `port_scanner.py` script is a versatile and advanced port scanner built with Python. It replicates many of the functionalities of the popular `nmap` tool, offering capabilities such as:

- **TCP Port Scanning** (default)
- **SYN Scanning**
- **UDP Port Scanning**
- **OS Detection**
- **Host Discovery** in a subnet
- Multi-threaded scanning for speed

## Features

1. **Scan Types**
   - TCP Scan (default)
   - SYN Scan (stealthy)
   - UDP Scan
2. **OS Detection** using ICMP packets and TTL values.
3. **Host Discovery** in a subnet using ICMP Echo requests.
4. **Threaded Scanning** for faster results.
5. **Flexible Input**:
   - Single ports
   - Comma-separated port lists
   - Port ranges
   - Port list files

## Prerequisites

To use the script, ensure you have the following:

- **Python 3.7+** installed on your system.
- **Administrative Privileges** (required for SYN and UDP scans).
- **Scapy Library** for advanced networking features.

## Installation

Clone the repository:

```bash
git clone https://github.com/cyb-swap/portscanner.git
cd portscanner
```

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run the script with the `-host` parameter to specify a target host. Add additional arguments as needed:

```bash
python port_scanner.py -host <TARGET_HOST> [OPTIONS]
```

### Options

| Argument  | Description                                                                                 |
| --------- | ------------------------------------------------------------------------------------------- |
| `-host`   | Target domain or IP address (required).                                                     |
| `-p`      | Ports to scan: single port, comma-separated list, or range (e.g., `22`, `80,443`, `20-25`). |
| `-iL`     | File containing a list of ports to scan.                                                    |
| `-os`     | Perform OS detection on the target host.                                                    |
| `-subnet` | Discover live hosts in a subnet (e.g., `192.168.1`).                                        |
| `-scan`   | Type of scan: `tcp`, `syn`, or `udp` (default: `tcp`).                                      |
| `-o`      | Save the scan results to a specified output file.                                           |

### Examples

#### 1. TCP Port Scan

Scan ports 80 and 443 on `example.com`:

```bash
python port_scanner.py -host example.com -p 80,443
```

#### 2. SYN Scan

Perform a SYN scan on ports 22 to 25:

```bash
python port_scanner.py -host example.com -p 22-25 -scan syn
```

#### 3. UDP Scan

Scan port 53 using UDP:

```bash
python port_scanner.py -host example.com -p 53 -scan udp
```

#### 4. OS Detection

Detect the operating system of a target:

```bash
python port_scanner.py -host example.com -os
```

#### 5. Host Discovery

Discover all live hosts in the `192.168.1` subnet:

```bash
python port_scanner.py -subnet 192.168.1
```

#### 6. Using a Port List File

Provide a file `ports.txt` containing ports to scan:

```bash
python port_scanner.py -host example.com -iL ports.txt
```

### Save Results

Save the scan results to a file:

```bash
python port_scanner.py -host example.com -p 80,443 -o results.txt
```

## Output

The script displays results in a clear format, such as:

```plaintext
    ==================================
    |         Advanced Port Scanner  |
    |          Built with Python     |
    ==================================
[+] Port 80 is OPEN
[-] Port 443 is CLOSED
[+] Host 192.168.1.1 is alive
```

## Contributing

Feel free to contribute to the project by submitting pull requests or reporting issues.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

