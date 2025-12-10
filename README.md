# 👁️ ARGOS PANOPTES

> **A blazing fast, concurrent network scanner written in pure Go.**
> *Built for speed, precision, and style.*

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## 📖 Overview

**Argos** is a next-generation TCP port scanner designed for Red Team operations and Network Administration. Unlike traditional threaded scanners, Argos leverages **Golang's Goroutines** and **Channels** to handle thousands of concurrent connections with minimal resource overhead.

Named after the Greek giant with a hundred eyes, this tool ensures nothing on your network goes unnoticed.

### ✨ Key Features

* **🚀 High Performance:** Scans massive networks in seconds using a Worker Pool architecture.
* **🎨 Cyberpunk UX:** Features a TrueColor gradient CLI interface with animated boot sequences and progress bars.
* **🌐 CIDR Support:** Natively supports subnet scanning (e.g., `192.168.1.0/24`).
* **🧠 Smart Fingerprinting:** Performs Banner Grabbing to identify running services (SSH, HTTP, FTP, etc.).
* **💾 JSON Export:** Outputs results to JSON for easy integration with other tools or reporting.
* **🛡️ Graceful Shutdown:** Handles `CTRL+C` interrupts cleanly without data loss.

---

## ⚡ Installation

### Prerequisites
* **Go 1.21** or higher installed on your machine.

### Build from Source

```bash
# 1. Clone the repository
git clone [https://github.com/StaiLee/Argos.git](https://github.com/StaiLee/Argos.git)
cd Argos

# 2. Build the binary
go build -o argos main.go

# 3. Verify installation
./argos -h
```

---

## 🚀 Usage

Argos is designed to be intuitive. The basic syntax is:

```bash
./argos -host <TARGET> [FLAGS]
```

### 🚩 Available Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-host` | Target IP or CIDR range (e.g., `192.168.1.1` or `10.0.0.0/24`) | `127.0.0.1` |
| `-p` | Ports to scan. Supports list (`80,443`), range (`1-1000`), or `all`. | `1-1024` |
| `-t` | Number of concurrent workers (threads). | `500` |
| `-timeout` | Connection timeout in milliseconds. | `500` |
| `-json` | File path to export results (e.g., `results.json`). | *(None)* |

### 💡 Examples

**1. Quick Health Check (Default)**
Scans the top 1024 ports of a single machine.
```bash
./argos -host 192.168.1.15
```

**2. The "Full Audit" (All Ports, High Speed)**
Scans all 65,535 ports with 1,000 workers.
```bash
./argos -host 10.10.10.5 -p all -t 1000
```

**3. Subnet Sweep (CIDR)**
Scans the entire `192.168.1.x` network for Web Services (80, 443).
```bash
./argos -host 192.168.1.0/24 -p 80,443
```

**4. Export Data**
Save the output for reporting.
```bash
./argos -host scanme.nmap.org -p 1-1000 -json report.json
```

---

## 🏗️ Technical Architecture

Argos was built to demonstrate the power of **Concurrency vs. Parallelism** in Network Engineering.

### The Worker Pool Pattern
Instead of spawning a new thread for every port (which crashes the OS), Argos uses a fixed pool of workers:

1.  **The Feeder:** A main Goroutine generates jobs (Target IP + Port) and pushes them into a buffered `channel`.
2.  **The Workers:** A user-defined number of workers (default: 500) pull jobs from the channel.
3.  **The WaitGroup:** Ensures the program waits for all workers to finish before exiting.
4.  **Context Management:** Uses `context.WithCancel` to allow instant, safe interruption of thousands of routines.

```mermaid
graph TD;
    Generator[Job Generator] -->|Push Port| Jobs(Channel: Jobs);
    Jobs --> Worker1[Worker 1];
    Jobs --> Worker2[Worker 2];
    Jobs --> Worker3[Worker 3];
    Worker1 -->|Result| Results(Channel: Results);
    Worker2 -->|Result| Results;
    Worker3 -->|Result| Results;
    Results --> Aggregator[Result Sorter & UI];
```

---

## ⚠️ Disclaimer

**Argos is intended for educational and authorized testing purposes only.**
Scanning networks without permission is illegal in many jurisdictions. The developers assume no liability for misuse of this tool.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
