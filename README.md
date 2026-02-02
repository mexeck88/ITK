# ITK: ICS Tool Kit

**A Modular, CLI-Driven Framework for ICS Security Auditing & CTF Competitions**

---

**ITK (ICS Tool Kit)** is a comprehensive command-line interface designed to streamline the discovery, enumeration, and exploitation of **Industrial Control Systems (ICS)** protocols. 

The project includes a **Dockerized Simulation Lab**, enabling users to practice against realistic targets in a safe, virtual environment.


## DEMO GOES HERE

![ITK DEMO](assets/demos/itk_demo.gif)

## Key Features

*   **Unified CLI Interface**: specific tools for Modbus, S7, BACnet, and EtherNet/IP under one roof.
*   **Modular Architecture**: Easily extensible plugin system for adding new protocol drivers. Great for custom protocols used often in CTFs!
*   **Automation Ready**: JSON output support (`--json`) for pipelining with other tools.
*   **Session Management**: Caches connection states to reduce overhead during rapid-fire operations.
*   **Simulation Lab**: Built-in Docker composition for "No-Hardware" testing.

## Installation

### Prerequisites

*   Python 3.8+
*   Docker & Docker Compose (for the simulation lab ONLY)

### Setup

Clone the repository and install the dependencies:

```bash
git clone https://github.com/mexeck88/itk.git
cd itk
pip install -r requirements.txt
```

## Usage

ITK uses a consistent syntax across all protocols:

```bash
python3 itk.py -t <TARGET_IP> <PROTOCOL> <COMMAND> [OPTIONS]
```

Global Options:
*   `-t, --target`: Target IP address (Required)
*   `-p, --port`: Target port (Optional, defaults to protocol standard)
*   `-v, --verbose`: Enable verbose output
*   `-j, --json`: Output results as JSON for use in other tools

### Supported Protocols & Examples

#### Modbus TCP
Enumerates and manipulates Coils, Discrete Inputs, and Holding Registers.

```bash
# Scan for active slave IDs
itk -t 192.168.1.10 modbus scan --slaves

# Read Holding Register 100
itk -t 192.168.1.10 modbus read 100 holding

# Write to Coil 0
itk -t 192.168.1.10 modbus write 0 coil 1
```

#### S7comm (Siemens)
Interacts with Siemens S7-300/400/1200/1500 PLCs.

```bash
# Get CPU Module Info
itk -t 192.168.1.10 s7 info

# Read 4 bytes from Data Block 1 at offset 0
itk -t 192.168.1.10 s7 read 1.0 db --size 4
```

#### BACnet/IP
Discovers Building Automation devices and objects.

```bash
# Scan network for devices (Who-Is)
itk -t 192.168.1.10 bacnet scan

# Write "ON" to Binary Output 1 (e.g., Door Lock)
itk -t 192.168.1.10 bacnet write 1 binary_output ON
```

#### EtherNet/IP (Allen-Bradley)
Browses and modifies tags on CIP-enabled devices.

```bash
# Enumerate all available tags
itk -t 192.168.1.10 enip scan

# Read a specific tag
itk -t 192.168.1.10 enip read FLAG tag
```

## ITK Lab

ITK includes 5 simulation boxes for testing the toolkit, these are simple docker containers that simulate the ICS/SCADA protocol. 


| Service | Host | Port | Description |
|---------|------|------|-------------|
| **Modbus TCP** | `localhost` | `5020` | Simulated PLC with Coils & Holding Registers. |
| **S7comm** | `localhost` | `1020` | Siemens S7-300 simulator (DB1, DB2, DB100). |
| **BACnet/IP** | `localhost` | `47808` | (UDP) Building Automation controller. |
| **EtherNet/IP**| `localhost` | `44818` | Allen-Bradley style PLC with CIP tags. |
| **BlackBox** | `localhost` | `19876` | Custom challenge service (TCP). |

```bash
# Generate all 5 boxes
docker-compose up -d

# Stop the lab
docker-compose down
```

## Demos

See ITK in action below.

### Modbus Enumeration
![Modbus Scan Demo](assets/demos/modbus_scan.gif)
*Scanning a target for Modbus registers and identifying active slave IDs.*

### Exploiting a BACnet Door Lock
![BACnet Exploit Demo](assets/demos/bacnet_exploit.gif)
*Locating a binary output controlling a lock and forcing it open.*

### JSON Output Integration
![JSON Pipeline Demo](assets/demos/json_pipe.gif)
*Piping ITK output into `jq` for automated processing.*

> **Note**: Add your GIF recordings to the `assets/demos/` directory to populate these placeholders.

## Roadmap

The project is evolving through defined phases:

*   **Phase 1: Core Framework** - CLI skeleton, Logging, Session Manager ( In Progress)
*   **Phase 2: Virtual Lab** - Dockerized Modbus, S7, BACnet, EnIP simulators (TODO)
*   **Phase 3: Protocol Drivers** - Full implementation of heavy lifting logic (TODO)
*   **Phase 4: Exploitation Modules** - DoS tools, Replay Engine, and Flag Hunter (TODO)
*   **Phase 5: Documentation** 

## Disclaimer

**ITK is for educational and authorized security auditing purposes only.**


**Do not use this tool on ICS networks or equipment you do not own or have explicit permission to test.** Industrial Control Systems are fragile; improper scanning can cause physical damage or process disruption. The authors are not responsible for any damage caused by the misuse of this tool. 

---
