# Week 06 — PCAP Analysis: Network Traffic Forensics & Object Reconstruction

> **Core Concept:** Network traffic captured in `.pcap` files contains the raw bytes of everything that crossed the wire — HTTP responses, file downloads, images, executables, credentials. With the right tools, we can *reconstruct* those objects byte-for-byte, just as if we downloaded them ourselves.

---

## Table of Contents

1. [What is a PCAP?](#1-what-is-a-pcap)
2. [Tool Landscape: Wireshark vs tcpdump vs Snort vs Scapy](#2-tool-landscape)
3. [Installing Wireshark & Setting Up tshark PATH](#3-installing-wireshark--setting-up-tshark)
4. [Unit 42 Tutorial — Exporting Objects from a PCAP (Replicated)](#4-unit-42-tutorial--exporting-objects-from-a-pcap)
5. [PCAP Analysis Standalone Toolkit — Setup & Usage](#5-pcap-analysis-standalone-toolkit)
6. [The 10 Analysis Scripts — What Each Does](#6-the-10-analysis-scripts)
7. [Object Reconstruction — The Core Idea](#7-object-reconstruction--the-core-idea)
8. [Required Packages & Installation](#8-required-packages--installation)
9. [Lab Exercise: Running All 10 Scripts](#9-lab-exercise-running-all-10-scripts)
10. [Further Reading](#10-further-reading)

---

## 1. What is a PCAP?

A **PCAP** (Packet CAPture) file is a binary file format for storing raw network packets. It is produced by tools like Wireshark, tcpdump, or any application using `libpcap`/`WinPcap`.

Each packet in a PCAP contains:

| Layer | What's Stored |
|-------|--------------|
| Link (Layer 2) | Ethernet frame, MAC addresses |
| Network (Layer 3) | IP header, source/destination IPs |
| Transport (Layer 4) | TCP/UDP header, ports, sequence numbers |
| Application (Layer 7) | HTTP request/response, DNS query, FTP data, etc. |

**Key insight:** When a browser downloads a file over HTTP, every byte of that file travels across the network inside TCP segments. A PCAP captures all of those segments. Tools like Wireshark can *reassemble* the TCP stream and reconstruct the original file — even days later from a saved capture.

---

## 2. Tool Landscape

Understanding *why* we use each tool is more important than memorising commands.

### 2.1 Wireshark (GUI)

- **What it is:** The most widely used open-source packet analyser. GUI-based.
- **Best for:** Interactive investigation, filtering, protocol decoding, object export.
- **Key feature:** `File → Export Objects` can extract HTTP files, SMB files, DICOM, IMF, and TFTP objects directly from a PCAP without writing a single line of code.
- **Website:** https://www.wireshark.org

### 2.2 tshark (CLI)

- **What it is:** The command-line version of Wireshark — same engine, terminal interface.
- **Best for:** Scripting, automation, running on servers without a GUI.
- **Installed with Wireshark** — when you install Wireshark, tshark comes along.
- Example:

```bash
# List all HTTP objects in a pcap
tshark -r http.cap --export-objects http,./exported_objects/

# Print all DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```

### 2.3 tcpdump (CLI — capture & read)

- **What it is:** Lightweight CLI tool for capturing live traffic OR reading pcap files. Linux/macOS native. Windows via WinDump.
- **Best for:** Capturing traffic on remote servers, quick packet inspection.
- **Does NOT** reconstruct application-layer objects — that's Wireshark/tshark's job.
- Example:

```bash
# Capture live traffic on interface eth0, save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read a pcap, filter only HTTP traffic (port 80)
tcpdump -r capture.pcap port 80

# Show packets with full hex + ASCII payload
tcpdump -r capture.pcap -X -s 0
```

### 2.4 Snort (IDS/IPS)

- **What it is:** An open-source Intrusion Detection System (IDS) / Intrusion Prevention System (IPS) by Cisco Talos.
- **Best for:** Rule-based threat detection — matching packet payloads against known malware signatures.
- **Works on:** Live traffic OR pcap files (offline analysis mode).
- **Not the same as Wireshark:** Snort doesn't visualise or reconstruct objects. It alerts on patterns.

```bash
# Run Snort against a pcap in IDS mode
snort -r capture.pcap -c /etc/snort/snort.conf -l ./logs/
```

### 2.5 Scapy (Python library)

- **What it is:** A Python library for packet crafting, parsing, and analysis. Used extensively in our 10-script toolkit.
- **Best for:** Custom analysis, scripting, building your own detections.

```python
from scapy.all import rdpcap, IP, TCP

packets = rdpcap("http.cap")
for pkt in packets:
    if IP in pkt:
        print(pkt[IP].src, "->", pkt[IP].dst)
```

### 2.6 Comparison Summary

| Tool | GUI | Live Capture | Object Export | Scripting | Threat Detection |
|------|-----|-------------|--------------|-----------|-----------------|
| Wireshark | ✅ | ✅ | ✅ | ❌ | ❌ |
| tshark | ❌ | ✅ | ✅ | ✅ | ❌ |
| tcpdump | ❌ | ✅ | ❌ | ✅ | ❌ |
| Snort | ❌ | ✅ | ❌ | ✅ (rules) | ✅ |
| Scapy | ❌ | ✅ | Custom | ✅ | Custom |

---

## 3. Installing Wireshark & Setting Up tshark

### 3.1 Windows

1. **Download** the latest stable installer from https://www.wireshark.org/download.html
2. Run the `.exe` installer.
3. During installation:
   - ✅ Check **"Install TShark"** (it's a checkbox — don't skip it)
   - ✅ Check **"Install USBPcap"** if needed
   - Install **Npcap** when prompted (the Windows packet capture driver)
4. After installation, add tshark to your PATH:

**Option A — Via Installer (Recommended)**
During the Wireshark install wizard, tick "Add Wireshark to PATH". This handles it automatically.

**Option B — Manual**
```
# Default install path:
C:\Program Files\Wireshark\

# Add this to System PATH:
# Control Panel → System → Advanced → Environment Variables
# → System Variables → Path → Edit → New
# Paste: C:\Program Files\Wireshark
```

**Verify:**
```cmd
tshark --version
wireshark --version
```

### 3.2 macOS

```bash
# Option 1: Homebrew (recommended)
brew install --cask wireshark
brew install wireshark  # installs tshark CLI

# After install, tshark is available at:
/usr/local/bin/tshark   # Intel Mac
/opt/homebrew/bin/tshark  # Apple Silicon

# Verify
tshark --version
```

If you used the `.dmg` installer instead:
```bash
# Add to PATH in ~/.zshrc or ~/.bash_profile
export PATH="/Applications/Wireshark.app/Contents/MacOS:$PATH"
source ~/.zshrc
```

### 3.3 Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install wireshark tshark -y

# During install: select "Yes" to allow non-superusers to capture
# (adds you to the wireshark group)

# Add your user to the wireshark group so you can capture without sudo
sudo usermod -aG wireshark $USER
newgrp wireshark

# Verify
tshark --version
which tshark
```

### 3.4 Verifying tshark is on PATH

Run this to confirm tshark is found correctly from any terminal:

```bash
# All platforms
tshark --version

# Expected output (example):
# TShark (Wireshark) 4.2.x
# ...
```

If you get `command not found`, double-check the directory containing `tshark.exe` (Windows) or `tshark` (Linux/Mac) is listed in your `PATH` environment variable.

---

## 4. Unit 42 Tutorial — Exporting Objects from a PCAP

> **Source:** [Wireshark Tutorial: Exporting Objects From a Pcap — Palo Alto Unit 42](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)
>
> **Author:** Brad Duncan | **Updated:** March 2024

### 4.1 Download the Lab PCAPs

The Unit 42 tutorial provides 5 PCAP files containing real (but safely packaged) malware traffic for analysis.

```
URL: https://github.com/PaloAltoNetworks/Unit42-Wireshark-tutorials/blob/main/
File: Wireshark-tutorial-extracting-objects-5-pcaps.zip
Password: infected
```

Extract the ZIP to get:
- `Wireshark-tutorial-extracting-objects-from-a-pcap-1-of-5.pcap`
- `Wireshark-tutorial-extracting-objects-from-a-pcap-2-of-5.pcap`
- `Wireshark-tutorial-extracting-objects-from-a-pcap-3-of-5.pcap`
- `Wireshark-tutorial-extracting-objects-from-a-pcap-4-of-5.pcap`
- `Wireshark-tutorial-extracting-objects-from-a-pcap-5-of-5.pcap`

> ⚠️ **Safety Note:** These PCAPs contain malware binaries embedded in HTTP traffic. The ZIP password `infected` is the standard convention in malware analysis to prevent accidental execution. Review these in an isolated environment (VM) or non-Windows OS.

### 4.2 Exporting HTTP Objects via Wireshark GUI

This is the most visual way to see object reconstruction in action.

**Steps:**

1. Open Wireshark
2. `File → Open` → select one of the 5 PCAPs
3. From the menu: `File → Export Objects → HTTP`
4. A dialog shows every HTTP object Wireshark can reconstruct:
   - Filename, hostname, content type, size, packet number
5. Click **Save All** to export every object, or select individual files and click **Save**

**What you'll find:**
- `.exe` — Windows executables (malware payloads)
- `.dll` — Dynamic link libraries
- `.doc`, `.xls` — Microsoft Office documents with macros
- Images, HTML pages, JavaScript files

### 4.3 Exporting HTTP Objects via tshark (CLI)

```bash
# Export all HTTP objects from pcap 1
tshark -r "Wireshark-tutorial-extracting-objects-from-a-pcap-1-of-5.pcap" \
  --export-objects http,./exported_http_objects/

# List what was exported
ls -lh ./exported_http_objects/
```

### 4.4 Exporting SMB Objects

Some PCAPs contain files transferred over SMB (Windows file sharing). The tutorial's PCAP 5 demonstrates this.

```
Wireshark GUI:
File → Export Objects → SMB
```

```bash
# tshark SMB export
tshark -r "Wireshark-tutorial-extracting-objects-from-a-pcap-5-of-5.pcap" \
  --export-objects smb,./exported_smb_objects/
```

### 4.5 Analysing Exported Files

Once objects are exported, treat them as you would any unknown file:

```bash
# Check file type (magic bytes, not extension)
file suspicious_file.bin

# Get SHA256 hash for VirusTotal lookup
sha256sum suspicious_file.bin    # Linux/Mac
certutil -hashfile suspicious_file.bin SHA256  # Windows

# Check strings for URLs, registry keys, IPs
strings suspicious_file.bin | grep -E "http|\.exe|HKEY"

# Submit hash to VirusTotal
# https://www.virustotal.com/
```

### 4.6 Replicated Workflow Summary

```
PCAP File
    │
    ▼
Wireshark / tshark
    │
    ├── Filter: HTTP traffic
    ├── Reassemble TCP streams
    └── Reconstruct application-layer objects
            │
            ▼
    Exported files (EXE, DLL, DOCX, images...)
            │
            ├── file / strings / sha256sum
            ├── VirusTotal lookup
            └── Sandbox / dynamic analysis
```

---

## 5. PCAP Analysis Standalone Toolkit

> **Repository:** https://github.com/MuhammadMuneeb007/pcap-analysis-standalone-toolkit

### 5.1 Clone or Download

```bash
# Option A: git clone
git clone https://github.com/MuhammadMuneeb007/pcap-analysis-standalone-toolkit.git
cd pcap-analysis-standalone-toolkit

# Option B: Manual download
# Go to the GitHub repo → Code → Download ZIP
# Extract and cd into the folder
```

### 5.2 Create a Virtual Environment

Always isolate your Python dependencies:

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 5.3 Install Required Packages

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Core required packages
python -m pip install scapy pandas matplotlib networkx

# Recommended packages (significantly improve output quality)
python -m pip install plotly folium requests geoip2

# Optional — only needed if not using tshark
python -m pip install pyshark
```

### 5.4 The http.cap Sample File

The repository includes `http.cap` — a classic PCAP file from the Wireshark sample captures library. It contains simple HTTP traffic over port 80 and is safe to analyse on any OS. All 10 scripts are pre-tested against this file.

---

## 6. The 10 Analysis Scripts

Each script is **standalone** — no imports between scripts, no shared state. Run them independently in any order. The recommended order below progresses from broad to specific.

### Recommended Execution Order

| Order | Script | Purpose |
|-------|--------|---------|
| 1st | `Analysis_10_Final_Summary.py` | High-level overview first — know what you're dealing with |
| 2nd | `Analysis_3_Protocol_Decoder.py` | What protocols are present? |
| 3rd | `Analysis_6_Flow_Statistics.py` | Who talked to whom, how much? |
| 4th | `Analysis_8_Timeline_Analysis.py` | When did events happen? |
| 5th | `Analysis_1_Traffic_Visualizer.py` | Network graph — see the connections visually |
| 6th | `Analysis_9_Host_Profiling.py` | Deep dive per host |
| 7th | `Analysis_4_Threat_Detection.py` | Flag suspicious behaviour |
| 8th | `Analysis_5_Credential_Hunter.py` | Find cleartext credentials |
| 9th | `Analysis_2_Object_Extractor.py` | Reconstruct files from traffic |
| 10th | `Analysis_7_GeoIP_Map.py` | Where in the world are these IPs? |

### Script-by-Script Breakdown

#### Analysis_1_Traffic_Visualizer.py
Builds a **communication graph** — nodes are hosts, edges are connections, edge weight reflects traffic volume.

**Outputs:**
- `communication_graph.png` — static image
- `communication_graph.html` — interactive, zoomable (Plotly)
- `edges.csv` — raw edge data (src, dst, bytes, packets)
- `traffic_animation.mp4` / `.gif` — shows traffic over time

```bash
python Analysis_1_Traffic_Visualizer.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_2_Object_Extractor.py
**The core object reconstruction script.** Extracts all files transferred over the network.

**Outputs:**
- `raw_exports/` — raw bytes of every reconstructed object
- `organized_objects/` — sorted by type (images, executables, documents...)
- `reports/object_inventory.csv` — metadata table
- `reports/capture_summary.json` — JSON summary

```bash
python Analysis_2_Object_Extractor.py --pcap http.cap --output-dir outputs
```

> 💡 This is the script that directly mirrors what Wireshark does with `File → Export Objects`.

---

#### Analysis_3_Protocol_Decoder.py
Decodes each protocol found in the PCAP and produces human-readable session summaries.

**Outputs:**
- `protocol_summary.csv` — counts per protocol
- `decoded_sessions.csv` — per-session decode (src, dst, protocol, payload preview)
- `protocol_summary.txt` — plaintext report

```bash
python Analysis_3_Protocol_Decoder.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_4_Threat_Detection.py
Rule-based threat scoring engine. Flags suspicious patterns:
- Port scanning behaviour
- Connections to unusual ports
- Known bad protocol combinations
- High packet rates (potential DoS)

**Outputs:**
- `alerts.csv` — one row per alert
- `alerts.json` — structured JSON (machine-readable)
- `alerts_summary.txt` — human-readable report

```bash
python Analysis_4_Threat_Detection.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_5_Credential_Hunter.py
Searches for **cleartext credentials** in unencrypted protocols:
- HTTP Basic Auth
- FTP USER/PASS
- Telnet sessions
- POP3/IMAP login sequences

**Outputs:**
- `credentials_found.csv` — protocol, IP, username, password
- `credential_summary.txt`

```bash
python Analysis_5_Credential_Hunter.py --pcap http.cap --output-dir outputs
```

> ⚠️ This demonstrates why encrypting all traffic (HTTPS, SFTP, SSH) matters. Cleartext protocols leak credentials to anyone with a packet capture.

---

#### Analysis_6_Flow_Statistics.py
Computes TCP/UDP flow statistics — treating each (src_ip, src_port, dst_ip, dst_port, protocol) tuple as a flow.

**Outputs:**
- `flows.csv` — all flows with bytes, packets, duration
- `heavy_flows.csv` — top bandwidth consumers
- `flow_summary.txt`

```bash
python Analysis_6_Flow_Statistics.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_7_GeoIP_Map.py
Maps external IP addresses to physical locations and plots them on a world map.

**Outputs:**
- `external_ips.csv` — IP, country, city, lat/lon, ASN
- `geoip_map.html` — interactive Folium world map with flow arcs
- `geoip_summary.txt`

```bash
# Basic run (uses free IP-API lookup — rate limited)
python Analysis_7_GeoIP_Map.py --pcap http.cap --output-dir outputs

# With local MaxMind database (no rate limits, more accurate)
python Analysis_7_GeoIP_Map.py --pcap http.cap --output-dir outputs \
  --geoip-db GeoLite2-City.mmdb
```

**Getting the GeoLite2 database (free):**
1. Register at https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb`
3. Pass its path with `--geoip-db`

---

#### Analysis_8_Timeline_Analysis.py
Creates a **temporal view** of traffic — packets-per-second, bursts, quiet periods.

**Outputs:**
- `traffic_over_time.csv` — timestamped traffic volumes (UTC)
- `timeline_plot.png` — time series chart
- `timeline_summary.txt`

```bash
python Analysis_8_Timeline_Analysis.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_9_Host_Profiling.py
Builds a profile for each host: what ports they listened on, what protocols they used, how much data they sent/received.

**Outputs:**
- `host_profiles.csv`
- `host_profiles.txt`

```bash
python Analysis_9_Host_Profiling.py --pcap http.cap --output-dir outputs
```

---

#### Analysis_10_Final_Summary.py
High-level executive summary of the entire PCAP. Run this first for a quick overview.

**Outputs:**
- `final_summary.txt`
- `final_summary.json`

```bash
python Analysis_10_Final_Summary.py --pcap http.cap --output-dir outputs
```

---

## 7. Object Reconstruction — The Core Idea

This is the conceptual heart of the week.

### How TCP Streaming Enables Reconstruction

When a server sends a 500KB image over HTTP:

1. The image is broken into ~350 TCP segments (~1460 bytes each)
2. Each segment travels as a separate IP packet
3. TCP sequence numbers guarantee order and detect gaps
4. The receiver's TCP stack reassembles them into the original 500KB stream
5. **A PCAP records every one of those segments**
6. Tools like Wireshark replay the reassembly process on the saved capture

The result: **we can recover the exact bytes of the file**, reconstruct it to disk, and open it — as if we had downloaded it ourselves at the time it was captured.

### What Can Be Reconstructed

| Protocol | Recoverable Objects |
|----------|-------------------|
| HTTP | Web pages, images, EXE/DLL downloads, ZIP files, any file |
| FTP (data channel) | Files uploaded or downloaded |
| SMB | Windows file share transfers |
| SMTP | Emails and attachments |
| DNS | Domain resolution history |
| Telnet / FTP | Cleartext credentials, commands typed |

### What Cannot Be Reconstructed (without keys)

| Protocol | Why |
|----------|-----|
| HTTPS/TLS | Encrypted — payload is ciphertext |
| SFTP | Encrypted SSH tunnel |
| WireGuard / IPSec | Encrypted VPN traffic |

> **Note:** TLS decryption is possible if you have the session keys (e.g., via browser's `SSLKEYLOGFILE` environment variable). This is used in advanced forensics.

---

## 8. Required Packages & Installation

### Complete Installation (all scripts, all features)

```bash
# Activate your venv first
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate       # Windows

# All packages at once
pip install \
  scapy \
  pandas \
  matplotlib \
  networkx \
  plotly \
  folium \
  requests \
  geoip2

# Verify key packages
python -c "import scapy; print('scapy OK')"
python -c "import pandas; print('pandas OK')"
python -c "import matplotlib; print('matplotlib OK')"
python -c "import folium; print('folium OK')"
```

### Package Reference

| Package | Used By | Why |
|---------|---------|-----|
| `scapy` | All scripts | Core packet parsing library |
| `pandas` | All scripts | Data manipulation, CSV output |
| `matplotlib` | Scripts 1, 8 | Static charts and graphs |
| `networkx` | Script 1 | Graph/network topology |
| `plotly` | Script 1 | Interactive HTML graphs |
| `folium` | Script 7 | Interactive world maps |
| `requests` | Script 7 | IP geolocation API calls |
| `geoip2` | Script 7 | Local MaxMind database reader |

### External Tool: tshark

Several scripts try to use `tshark` for deeper protocol decoding. They fall back gracefully to `scapy` if tshark isn't found, but tshark gives significantly better results for HTTP object extraction.

```bash
# Confirm tshark is accessible from your Python environment
import subprocess
result = subprocess.run(["tshark", "--version"], capture_output=True)
print(result.stdout.decode())
```

---

## 9. Lab Exercise: Running All 10 Scripts

Work through this sequentially. Each command writes to an isolated subdirectory.

```bash
# 0. Setup
git clone https://github.com/MuhammadMuneeb007/pcap-analysis-standalone-toolkit.git
cd pcap-analysis-standalone-toolkit
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install scapy pandas matplotlib networkx plotly folium requests geoip2

# 1. High-level summary
python Analysis_10_Final_Summary.py --pcap http.cap --output-dir outputs

# 2. Protocol breakdown
python Analysis_3_Protocol_Decoder.py --pcap http.cap --output-dir outputs

# 3. Flow statistics
python Analysis_6_Flow_Statistics.py --pcap http.cap --output-dir outputs

# 4. Timeline
python Analysis_8_Timeline_Analysis.py --pcap http.cap --output-dir outputs

# 5. Traffic graph
python Analysis_1_Traffic_Visualizer.py --pcap http.cap --output-dir outputs

# 6. Host profiles
python Analysis_9_Host_Profiling.py --pcap http.cap --output-dir outputs

# 7. Threat detection
python Analysis_4_Threat_Detection.py --pcap http.cap --output-dir outputs

# 8. Credential hunting
python Analysis_5_Credential_Hunter.py --pcap http.cap --output-dir outputs

# 9. Object extraction (KEY SCRIPT)
python Analysis_2_Object_Extractor.py --pcap http.cap --output-dir outputs

# 10. GeoIP mapping
python Analysis_7_GeoIP_Map.py --pcap http.cap --output-dir outputs
```

### Expected Output Directory Structure

```
outputs/
└── http/
    ├── Analysis_1_Traffic_Visualizer/
    │   ├── communication_graph.png
    │   ├── communication_graph.html
    │   └── edges.csv
    ├── Analysis_2_Object_Extractor/
    │   ├── raw_exports/
    │   ├── organized_objects/
    │   └── reports/
    │       ├── object_inventory.csv
    │       └── capture_summary.json
    ├── Analysis_3_Protocol_Decoder/
    │   ├── protocol_summary.csv
    │   ├── decoded_sessions.csv
    │   └── protocol_summary.txt
    ├── Analysis_4_Threat_Detection/
    │   ├── alerts.csv
    │   ├── alerts.json
    │   └── alerts_summary.txt
    ├── Analysis_5_Credential_Hunter/
    │   ├── credentials_found.csv
    │   └── credential_summary.txt
    ├── Analysis_6_Flow_Statistics/
    │   ├── flows.csv
    │   ├── heavy_flows.csv
    │   └── flow_summary.txt
    ├── Analysis_7_GeoIP_Map/
    │   ├── external_ips.csv
    │   ├── geoip_map.html
    │   └── geoip_summary.txt
    ├── Analysis_8_Timeline_Analysis/
    │   ├── traffic_over_time.csv
    │   ├── timeline_plot.png
    │   └── timeline_summary.txt
    ├── Analysis_9_Host_Profiling/
    │   ├── host_profiles.csv
    │   └── host_profiles.txt
    └── Analysis_10_Final_Summary/
        ├── final_summary.txt
        └── final_summary.json
```

---

## 10. Further Reading

| Resource | Link |
|----------|------|
| Unit 42 Wireshark Tutorial Series | https://unit42.paloaltonetworks.com/tag/wireshark-tutorial/ |
| Wireshark Official Docs | https://www.wireshark.org/docs/ |
| Wireshark Display Filter Reference | https://www.wireshark.org/docs/dfref/ |
| Scapy Documentation | https://scapy.readthedocs.io/ |
| Wireshark Sample Captures (incl. http.cap) | https://wiki.wireshark.org/SampleCaptures |
| MaxMind GeoLite2 (Free GeoIP DB) | https://dev.maxmind.com/geoip/geolite2-free-geolocation-data |
| Snort IDS Rules | https://www.snort.org/downloads |
| PCAP Analysis Toolkit (This week's repo) | https://github.com/MuhammadMuneeb007/pcap-analysis-standalone-toolkit |

---

*Week 06 — Network Forensics & PCAP Analysis*
