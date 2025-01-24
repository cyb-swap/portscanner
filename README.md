# Advanced Python Port Scanner

This project is a comprehensive port scanner built in Python, designed to offer functionality similar to the well-known Nmap tool. It supports multiple scanning techniques and includes features such as OS detection, host discovery, and threaded scanning for efficiency.

---

## Features

- **TCP Scan**: Determines if ports are open using standard TCP connections.
- **SYN Scan**: Performs stealthy SYN scans to identify open ports.
- **UDP Scan**: Identifies open UDP ports.
- **Host Discovery**: Finds live hosts within a subnet.
- **OS Detection**: Identifies the operating system of a target using TTL values.
- **Threaded Scanning**: Utilizes multiple threads for faster port scanning.

---

## Requirements

### Install Dependencies

The project requires Python 3.6 or newer and the `scapy` library for packet crafting. Use the following commands to install the dependencies:

```bash
pip install -r requirements.txt
```

Dependencies include:

- `scapy`

---

## Usage

Run the script using the command line with various options to perform different types of scans. The following sections outline the available arguments.

### Arguments

| Argument  | Description                                                          |
| --------- | -------------------------------------------------------------------- |
| `-host`   | Target domain or IP address (Required).                              |
| `-p`      | Ports to scan. Comma-separated (e.g., 22,80) or range (e.g., 1-100). |
| `-iL`     | File containing a list of ports to scan.                             |
| `-os`     | Perform OS detection on the target host.                             |
| `-subnet` | Discover live hosts in a specified subnet (e.g., 192.168.1).         |
| `-scan`   | Scan type: `tcp`, `syn`, or `udp`. Default is `tcp`.                 |
| `-o`      | Output file to save scan results.                                    |

### Examples

#### Perform a TCP Scan on Specific Ports

```bash
python port_scanner.py -host 192.168.1.1 -p 22,80,443 -scan tcp
```

#### Perform a SYN Scan on a Range of Ports

```bash
python port_scanner.py -host 192.168.1.1 -p 1-100 -scan syn
```

#### Perform a UDP Scan Using a Port List File

```bash
python port_scanner.py -host 192.168.1.1 -iL ports.txt -scan udp
```

#### Perform OS Detection

```bash
python port_scanner.py -host 192.168.1.1 -os
```

#### Perform Host Discovery in a Subnet

```bash
python port_scanner.py -subnet 192.168.1
```

---

## Output

The script outputs scan results directly to the terminal. Optionally, you can save the results to a file using the `-o` argument:

```bash
python port_scanner.py -host 192.168.1.1 -p 22,80 -o results.txt
```

---

## Notes

- Ensure you have administrative or root privileges for certain scanning techniques like SYN scans.
- Use this tool responsibly and only on networks you have permission to test.

---

## License

This project is provided for educational purposes only and is licensed under the MIT License.

---

## Contribution

Contributions and improvements are welcome! Feel free to submit pull requests or issues on the [GitHub repository](https://github.com/cyb-swap/portscanner).

