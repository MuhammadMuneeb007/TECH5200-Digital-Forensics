# 🧠 Memory Forensics: A Complete Practical Guide
### TECH5200 — Digital Forensics | Memory Acquisition, Dump Analysis & Tool Comparison

---

## Table of Contents

1. [Core Terminology](#1-core-terminology)
2. [Memory Acquisition Tools Overview](#2-memory-acquisition-tools-overview)
3. [LIME — Linux Memory Extractor](#3-lime--linux-memory-extractor)
4. [WinPmem — Windows Memory Acquisition](#4-winpmem--windows-memory-acquisition)
5. [LIME vs WinPmem — Key Differences](#5-lime-vs-winpmem--key-differences)
6. [Memory Analysis Tools Comparison](#6-memory-analysis-tools-comparison)
7. [Installing Volatility 3](#7-installing-volatility-3)
8. [Volatility 3 — Complete Cheat Sheet](#8-volatility-3--complete-cheat-sheet)
9. [Full Practical Workflow (Windows)](#9-full-practical-workflow-windows)
10. [Extracting & Triaging Artifacts](#10-extracting--triaging-artifacts)
11. [Common Errors & Fixes](#11-common-errors--fixes)
12. [Summary Cheat Sheet](#12-summary-cheat-sheet)

---

## 1. Core Terminology

Understanding the language of memory forensics is essential before touching any tool.

| Term | Definition | Example |
|---|---|---|
| **Memory Acquisition** | The act of capturing live RAM and saving it to a file | Running WinPmem to produce `memory.raw` |
| **Memory Dump** | The saved RAM file on disk — a snapshot of RAM at a point in time | `memory.raw`, `memory.dmp`, `sample.vmem` |
| **Memory Dump Analysis** | Analyzing that saved file using a forensic tool | `vol.exe -f memory.raw windows.pslist` |
| **Memory Analysis** | The broader umbrella term — can include live RAM or dump file investigation | Examining malware artifacts in RAM |
| **Volatile Data** | Data that only exists in RAM and is lost when power is removed | Running processes, open network sockets, encryption keys |
| **Artefact** | A forensically significant piece of evidence found in memory | A process name, injected shellcode, a decrypted password |

> **In this practical:**
> - **WinPmem** performs memory acquisition → produces `memory.raw`
> - **Volatility 3** performs memory dump analysis on `memory.raw`

---

## 2. Memory Acquisition Tools Overview

Before analysis can begin, RAM must be captured. Different tools exist for different operating systems.

| Tool | OS | Output Format | Notes |
|---|---|---|---|
| **WinPmem** | Windows | `.raw` | Open source, lightweight, PTE Remapping mode |
| **LIME** | Linux / Android | `.lime`, `.raw` | Kernel module-based, must be compiled |
| **DumpIt** | Windows | `.raw` / `.dmp` | Simple one-click acquisition |
| **Magnet RAM Capture** | Windows | `.raw` | GUI-based, beginner friendly |
| **FTK Imager** | Windows | `.mem` | Commercial, also does disk imaging |
| **OSXPmem** | macOS | `.raw` | Part of the Pmem family |
| **avml** | Linux | `.raw` | Microsoft's open source Linux acquirer |

---

## 3. LIME — Linux Memory Extractor

### What Is LIME?

**LiME** (Linux Memory Extractor) is a **Loadable Kernel Module (LKM)** that allows full physical memory acquisition on Linux-based systems, including Android devices. It is the standard tool for Linux memory forensics.

- GitHub: [https://github.com/504ensicslabs/lime](https://github.com/504ensicslabs/lime)
- Works by inserting a kernel module that reads `/dev/mem` directly
- Can output over a network (TCP) or to a local file

### LIME Installation & Compilation

```bash
# Step 1 — Install build dependencies
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) git -y

# Step 2 — Clone the repository
git clone https://github.com/504ensicslabs/lime.git
cd lime/src

# Step 3 — Compile the kernel module
make

# Output will be a .ko file, e.g.:
# lime-5.15.0-91-generic.ko
```

### LIME Cheat Codes (Commands)

```bash
# ── ACQUIRE TO LOCAL FILE ──────────────────────────────────────────
sudo insmod lime-$(uname -r).ko "path=/home/user/memory.lime format=lime"

# ── ACQUIRE IN RAW FORMAT (Volatility-compatible) ──────────────────
sudo insmod lime-$(uname -r).ko "path=/home/user/memory.raw format=raw"

# ── ACQUIRE OVER NETWORK (send to forensic workstation) ────────────
# On the TARGET (suspect) machine:
sudo insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"

# On the FORENSIC workstation (receive and save):
nc <target_ip> 4444 > memory.lime

# ── ACQUIRE WITH PADDING (preserves memory layout) ─────────────────
sudo insmod lime-$(uname -r).ko "path=/home/user/memory.lime format=padded"

# ── REMOVE THE MODULE AFTER ACQUISITION ────────────────────────────
sudo rmmod lime

# ── VERIFY ACQUISITION (check file size matches expected RAM) ───────
ls -lh memory.lime
free -h

# ── HASH THE DUMP FOR CHAIN OF CUSTODY ─────────────────────────────
sha256sum memory.lime > memory.lime.sha256
md5sum memory.lime   > memory.lime.md5
```

### LIME Output Formats

| Format | Description | Use With |
|---|---|---|
| `lime` | LIME native format with headers | Volatility, Rekall |
| `raw` | Flat binary, no headers | Volatility (most compatible) |
| `padded` | Raw with zero-padding to preserve addressing | Volatility |

---

## 4. WinPmem — Windows Memory Acquisition

### What Is WinPmem?

**WinPmem** is an open-source Windows memory acquisition tool by the Velocidex team (creators of Velociraptor). It installs a temporary kernel driver to safely read physical memory.

- Download: [https://github.com/Velocidex/WinPmem/releases](https://github.com/Velocidex/WinPmem/releases)
- No installation required — single `.exe`
- Must be run as **Administrator**

### WinPmem Usage

```bat
:: Step 1 — Open Command Prompt as Administrator

:: Step 2 — Navigate to the folder containing winpmem
cd /d C:\Users\munee\Desktop\PhD\Teaching\TECH5200\RAMCapture

:: Step 3 — Acquire memory to a RAW file
winpmem_mini_x64_rc2.exe memory.raw

:: Step 4 — Verify the file was created
dir memory.raw

:: Optional — Acquire with a specific output path
winpmem_mini_x64_rc2.exe C:\Evidence\memory.raw
```

### What WinPmem Does Internally

When you run WinPmem it:

1. Extracts a temporary kernel driver to `%TEMP%`
2. Loads the driver to gain kernel-level memory access
3. Reads all physical memory ranges (skipping hardware-mapped regions)
4. Writes a flat `.raw` image to disk
5. Unloads and deletes the driver automatically

The output you saw in your run is normal — the `x` characters indicate **inaccessible memory pages** (hardware-reserved), while `.` indicates successful page reads.

---

## 5. LIME vs WinPmem — Key Differences

| Feature | LIME | WinPmem |
|---|---|---|
| **Operating System** | Linux, Android | Windows only |
| **Mechanism** | Loadable Kernel Module (LKM) | Temporary kernel driver (`.sys`) |
| **Compilation Required** | ✅ Yes — must match running kernel version | ❌ No — pre-built binary |
| **Network Acquisition** | ✅ Yes — built-in TCP streaming | ❌ No |
| **Output Formats** | `lime`, `raw`, `padded` | `raw` only |
| **Anti-forensics Resistance** | Higher — network mode leaves minimal disk trace | Lower — writes directly to disk |
| **Ease of Use** | Moderate — requires kernel headers | Easy — single executable |
| **Android Support** | ✅ Yes | ❌ No |
| **Open Source** | ✅ Yes | ✅ Yes |
| **Volatility Compatible** | ✅ Yes (raw or lime format) | ✅ Yes |
| **Chain of Custody** | Manual hashing required | Manual hashing required |

### When to Use Each

```
Use LIME when:
  → Target is a Linux server, workstation, or Android device
  → You want to acquire over the network to avoid writing to suspect disk
  → You need maximum forensic soundness on Linux

Use WinPmem when:
  → Target is a Windows machine
  → You need a fast, no-install, single-binary solution
  → You are running a Windows forensics lab
```

---

## 6. Memory Analysis Tools Comparison

Once a memory dump exists, it must be analyzed. The three major tools are:

### Volatility 3

The most widely used open-source memory forensics framework. Plugin-based, Python-powered, and cross-platform.

```
Strengths:
  ✔ Huge plugin library (processes, network, registry, malware detection)
  ✔ Supports Windows, Linux, macOS dumps
  ✔ Active community and development
  ✔ Works on raw, lime, vmem, dmp, and more
  ✔ No profile needed in Volatility 3 (auto-detected)

Weaknesses:
  ✗ Can be slow on large dumps
  ✗ Command-line only (no GUI)
  ✗ Requires Python environment setup
```

### Rekall

A fork of Volatility (now largely unmaintained) that focused on live memory analysis.

```
Strengths:
  ✔ Could analyze live memory without a dump file
  ✔ Faster for some operations
  ✔ Supported Google's GRR remote forensics platform

Weaknesses:
  ✗ Project is effectively deprecated (no active development since ~2019)
  ✗ Many plugins no longer maintained
  ✗ Not recommended for new forensic workflows
```

### WinDbg

Microsoft's kernel debugger — not a forensics tool by design, but powerful for deep Windows analysis.

```
Strengths:
  ✔ Extremely deep Windows kernel analysis
  ✔ Official Microsoft support and documentation
  ✔ Can analyze crash dumps (.dmp) natively
  ✔ Supports live kernel debugging over network

Weaknesses:
  ✗ Windows-only
  ✗ Steep learning curve — designed for developers, not forensicators
  ✗ No built-in forensic reporting
  ✗ Requires symbol files from Microsoft servers
```

### Tool Selection Summary

| Scenario | Recommended Tool |
|---|---|
| Windows RAM forensics (general) | **Volatility 3** |
| Linux RAM forensics | **Volatility 3** |
| macOS RAM forensics | **Volatility 3** |
| Deep Windows kernel crash analysis | **WinDbg** |
| Legacy Volatility 2 workflows | **Volatility 2** (still available) |
| Live memory without a dump | **Rekall** (deprecated, use with caution) |

---

## 7. Installing Volatility 3

```bat
:: ── WINDOWS INSTALLATION ──────────────────────────────────────────

:: Option A — Install via pip (recommended)
python -m pip install volatility3

:: Option B — Install from source
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

:: Verify installation
python -c "import volatility3; print('Volatility 3 installed successfully')"

:: Find the vol executable
where vol

:: Test with help flag
vol -h
```

```bash
# ── LINUX INSTALLATION ──────────────────────────────────────────────

git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -e .

# Verify
python3 -c "import volatility3; print('OK')"
vol -h
```

---

## 8. Volatility 3 — Complete Cheat Sheet

> Replace `vol` with your full path if needed:
> `"C:\Users\munee\AppData\Local\Schrodinger\PyMOL2\envs\n8n-env\Scripts\vol.exe"`
>
> Replace `memory.raw` with your actual dump file path.

---

### 8.1 Processes & Threads

```bat
:: List all running processes (standard)
vol -f memory.raw windows.pslist.PsList

:: Process tree (parent-child relationships)
vol -f memory.raw windows.pstree.PsTree

:: Detect hidden/unlinked processes (rootkit detection)
vol -f memory.raw windows.psscan.PsScan

:: Compare pslist vs psscan to find hidden processes
vol -f memory.raw windows.psscan.PsScan > psscan.txt
vol -f memory.raw windows.pslist.PsList > pslist.txt

:: List threads
vol -f memory.raw windows.threads.Threads

:: Show DLLs loaded by each process
vol -f memory.raw windows.dlllist.DllList

:: Show DLLs for a specific PID
vol -f memory.raw windows.dlllist.DllList --pid 1234
```

### 8.2 Command Line & Console History

```bat
:: Show command-line arguments for all processes
vol -f memory.raw windows.cmdline.CmdLine

:: Extract console command history (typed commands)
vol -f memory.raw windows.consoles.Consoles
```

### 8.3 Network Connections

```bat
:: Show active and recently closed network connections
vol -f memory.raw windows.netstat.NetStat

:: Scan memory for network socket structures
vol -f memory.raw windows.netscan.NetScan
```

### 8.4 Registry

```bat
:: List registry hives in memory
vol -f memory.raw windows.registry.hivelist.HiveList

:: Print keys from a specific hive
vol -f memory.raw windows.registry.printkey.PrintKey --offset 0xADDRESS

:: Search for a specific registry key
vol -f memory.raw windows.registry.printkey.PrintKey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

:: Dump registry hive to file
vol -f memory.raw windows.registry.hivescan.HiveScan
```

### 8.5 Files & Filesystem

```bat
:: Scan for file objects in memory
vol -f memory.raw windows.filescan.FileScan

:: Dump all accessible files from memory
vol -f memory.raw windows.dumpfiles.DumpFiles -o ExtractedObjects\

:: Dump a specific file by virtual address
vol -f memory.raw windows.dumpfiles.DumpFiles --virtaddr 0xADDRESS -o ExtractedObjects\
```

### 8.6 Handles

```bat
:: List all open handles (files, registry, processes)
vol -f memory.raw windows.handles.Handles

:: Handles for a specific process
vol -f memory.raw windows.handles.Handles --pid 1234
```

### 8.7 Memory Sections & Injection Detection

```bat
:: List virtual address descriptors (memory mappings per process)
vol -f memory.raw windows.vadinfo.VadInfo

:: Scan for injected code (executable memory not backed by a file)
vol -f memory.raw windows.malfind.Malfind

:: Dump suspicious memory regions found by malfind
vol -f memory.raw windows.malfind.Malfind -o ExtractedObjects\
```

### 8.8 Services & Drivers

```bat
:: List Windows services
vol -f memory.raw windows.svcscan.SvcScan

:: List loaded kernel drivers
vol -f memory.raw windows.driverscan.DriverScan

:: List kernel modules
vol -f memory.raw windows.modules.Modules

:: Detect hidden kernel modules
vol -f memory.raw windows.modscan.ModScan
```

### 8.9 User Activity & Credentials

```bat
:: Extract cached password hashes (SAM / LSASS)
vol -f memory.raw windows.hashdump.Hashdump

:: Extract LSA secrets
vol -f memory.raw windows.lsadump.Lsadump

:: List recently accessed user sessions
vol -f memory.raw windows.sessions.Sessions

:: Extract clipboard content
vol -f memory.raw windows.clipboard.Clipboard

:: List desktop and window information
vol -f memory.raw windows.desktops.Desktops

:: Extract IE/Edge browser history artifacts
vol -f memory.raw windows.iehist.IEHistory
```

### 8.10 Kernel & System Info

```bat
:: Show OS version and system info from memory
vol -f memory.raw windows.info.Info

:: List system call table (SSDT) — detect hooks
vol -f memory.raw windows.ssdt.SSDT

:: Show boot time and system uptime
vol -f memory.raw windows.statistics.Statistics
```

### 8.11 Linux Memory Analysis (LIME dumps)

```bash
# List processes
vol -f memory.lime linux.pslist.PsList

# List network connections
vol -f memory.lime linux.netstat.Netstat

# Bash history from memory
vol -f memory.lime linux.bash.Bash

# List loaded kernel modules
vol -f memory.lime linux.lsmod.Lsmod

# Detect hidden modules
vol -f memory.lime linux.check_modules.Check_modules

# Scan for files
vol -f memory.lime linux.find_file.FindFile

# Mounted filesystems
vol -f memory.lime linux.mountinfo.MountInfo
```

---

## 9. Full Practical Workflow (Windows)

This is the complete step-by-step workflow used in TECH5200.

### Step 1 — Set Up Directory Structure

```bat
cd /d C:\Users\munee\Desktop\PhD\Teaching\TECH5200

mkdir RAMCapture
mkdir VolatilityOutputs
mkdir ExtractedObjects
mkdir ExtractedImages
mkdir ExtractedTextFiles
mkdir ExtractedNotepadMemory
```

### Step 2 — Fix Encoding (Run This Every Session)

```bat
chcp 65001
set PYTHONIOENCODING=utf-8
```

> This prevents the `UnicodeEncodeError` when Volatility outputs non-ASCII characters.

### Step 3 — Acquire Memory

```bat
:: Run as Administrator
cd RAMCapture
winpmem_mini_x64_rc2.exe memory.raw
```

### Step 4 — Define the Volatility Executable Variable

```bat
set VOL="C:\Users\munee\AppData\Local\Schrodinger\PyMOL2\envs\n8n-env\Scripts\vol.exe"
set DUMP=RAMCapture\memory.raw
set OUT=VolatilityOutputs
```

### Step 5 — Run Core Analysis Plugins

```bat
:: System info
%VOL% -f %DUMP% windows.info.Info > %OUT%\info.txt

:: Processes
%VOL% -f %DUMP% windows.pslist.PsList   > %OUT%\pslist.txt
%VOL% -f %DUMP% windows.pstree.PsTree   > %OUT%\pstree.txt
%VOL% -f %DUMP% windows.psscan.PsScan   > %OUT%\psscan.txt

:: Command line activity
%VOL% -f %DUMP% windows.cmdline.CmdLine     > %OUT%\cmdline.txt
%VOL% -f %DUMP% windows.consoles.Consoles   > %OUT%\consoles.txt

:: Network
%VOL% -f %DUMP% windows.netscan.NetScan > %OUT%\netscan.txt

:: Registry
%VOL% -f %DUMP% windows.registry.hivelist.HiveList > %OUT%\hivelist.txt

:: File objects
%VOL% -f %DUMP% windows.filescan.FileScan > %OUT%\filescan.txt

:: Services & drivers
%VOL% -f %DUMP% windows.svcscan.SvcScan     > %OUT%\svcscan.txt
%VOL% -f %DUMP% windows.driverscan.DriverScan > %OUT%\driverscan.txt

:: DLLs
%VOL% -f %DUMP% windows.dlllist.DllList > %OUT%\dlllist.txt

:: Malware detection
%VOL% -f %DUMP% windows.malfind.Malfind > %OUT%\malfind.txt
```

---

## 10. Extracting & Triaging Artifacts

### Extract All Accessible Files from Memory

```bat
%VOL% -f %DUMP% windows.dumpfiles.DumpFiles -o ExtractedObjects\
```

### Find Image Files in the Filescan Output

```bat
findstr /i ".jpg .jpeg .png .bmp .gif .webp .tif .tiff" VolatilityOutputs\filescan.txt > VolatilityOutputs\image_candidates.txt
notepad VolatilityOutputs\image_candidates.txt
```

### Find Text & Document Files

```bat
findstr /i ".txt .log .md .csv .ini .json .xml .rtf .docx .pdf" VolatilityOutputs\filescan.txt > VolatilityOutputs\text_candidates.txt
notepad VolatilityOutputs\text_candidates.txt
```

### Dump a Specific File by Virtual Address

```bat
:: Get the virtual address from filescan.txt, then:
%VOL% -f %DUMP% windows.dumpfiles.DumpFiles --virtaddr 0x<ADDRESS> -o ExtractedObjects\
```

### Extract Notepad Content from Memory

```bat
:: Find notepad processes
findstr /i "notepad" VolatilityOutputs\pslist.txt

:: Dump notepad's memory by PID
%VOL% -f %DUMP% windows.memmap.Memmap --pid <NOTEPAD_PID> --dump -o ExtractedNotepadMemory\

:: Search the dumped memory for text strings
strings ExtractedNotepadMemory\pid.<PID>.dmp | findstr /i "password secret"
```

### Triage Suspicious Processes

```bat
:: Check if anything in pslist is NOT in psscan (hidden processes)
:: (Do this manually — hidden processes are a rootkit indicator)

:: Get command lines of suspicious PIDs
%VOL% -f %DUMP% windows.cmdline.CmdLine --pid <SUSPICIOUS_PID>

:: Dump the process executable
%VOL% -f %DUMP% windows.dumpfiles.DumpFiles --pid <SUSPICIOUS_PID> -o ExtractedObjects\
```

---

## 11. Common Errors & Fixes

### UnicodeEncodeError (cp1252)

```
UnicodeEncodeError: 'charmap' codec can't encode characters in position 15-22
```

**Fix:**
```bat
chcp 65001
set PYTHONIOENCODING=utf-8
```
Run both lines before every Volatility session.

---

### Volatility Cannot Find Symbol Tables

```
Unsatisfied requirement for automagic: windows.kernelBase
```

**Fix:** Download Windows symbol packs from the Volatility Foundation:
```bat
:: Symbols go into:
volatility3\volatility3\symbols\windows\
:: Or set environment variable:
set VOLATILITY_SYMBOL_DIRS=C:\path\to\symbols
```

---

### "vol is not recognised" Error

```bat
:: Use the full path
"C:\Users\munee\AppData\Local\Schrodinger\PyMOL2\envs\n8n-env\Scripts\vol.exe" -h

:: Or run as a Python module
python -m volatility3 -f memory.raw windows.pslist.PsList
```

---

### WinPmem Driver Error

```
Error: Cannot load driver
```

**Fix:** Ensure Command Prompt is opened **as Administrator** (right-click → Run as administrator).

---

## 12. Summary Cheat Sheet

```
┌─────────────────────────────────────────────────────────────────────┐
│                   MEMORY FORENSICS QUICK REFERENCE                  │
├──────────────────────┬──────────────────────────────────────────────┤
│ ACQUISITION          │ COMMAND                                      │
├──────────────────────┼──────────────────────────────────────────────┤
│ Windows (WinPmem)    │ winpmem_mini_x64_rc2.exe memory.raw          │
│ Linux to file        │ insmod lime.ko "path=memory.raw format=raw"  │
│ Linux over network   │ insmod lime.ko "path=tcp:4444 format=lime"   │
│ Receive over network │ nc <ip> 4444 > memory.lime                   │
├──────────────────────┼──────────────────────────────────────────────┤
│ ANALYSIS PLUGIN      │ COMMAND                                      │
├──────────────────────┼──────────────────────────────────────────────┤
│ System Info          │ windows.info.Info                            │
│ Process List         │ windows.pslist.PsList                        │
│ Process Tree         │ windows.pstree.PsTree                        │
│ Hidden Processes     │ windows.psscan.PsScan                        │
│ Command History      │ windows.cmdline.CmdLine                      │
│ Console History      │ windows.consoles.Consoles                    │
│ Network Connections  │ windows.netscan.NetScan                      │
│ Registry Hives       │ windows.registry.hivelist.HiveList           │
│ File Scan            │ windows.filescan.FileScan                    │
│ Dump Files           │ windows.dumpfiles.DumpFiles -o <dir>         │
│ DLL List             │ windows.dlllist.DllList                      │
│ Services             │ windows.svcscan.SvcScan                      │
│ Kernel Drivers       │ windows.driverscan.DriverScan                │
│ Malware Detection    │ windows.malfind.Malfind                      │
│ Password Hashes      │ windows.hashdump.Hashdump                    │
│ Handles              │ windows.handles.Handles                      │
├──────────────────────┼──────────────────────────────────────────────┤
│ ENCODING FIX         │ chcp 65001 && set PYTHONIOENCODING=utf-8     │
└──────────────────────┴──────────────────────────────────────────────┘
```

---

*Guide prepared for TECH5200 — Digital Forensics Practical*
*Covers: WinPmem · LIME · Volatility 3 · Rekall · WinDbg*
