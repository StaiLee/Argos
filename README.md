# 👁️ ARGOS

> **A blazing fast, concurrent network scanner written in pure Go.** > *Built for speed, precision, and style.*

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
cd argos

# 2. Build the binary
go build -o argos main.go

# 3. Verify installation
./argos -h