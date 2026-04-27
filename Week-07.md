# Week 07 — Mobile Forensics

---

## Table of Contents

1. [Android Forensics (ADB)](#android-forensics-adb)
   - [Installation](#installation)
   - [Connecting Your Phone](#connecting-your-phone)
   - [Device Identification](#device-identification--enumeration)
   - [Logical Data Acquisition](#logical-data-acquisition)
   - [File System Browsing](#file-system-browsing)
   - [Extracting SQLite Databases](#extracting-sqlite-databases)
   - [Live Evidence Commands](#live-evidence-commands)
   - [Screen & Activity Capture](#screen--activity-capture)
   - [Logcat (System Logs)](#logcat-system--app-logs)
   - [Physical Acquisition](#physical-acquisition-root-required)
   - [Useful Forensic Utilities](#useful-forensic-utilities)
   - [Recommended Forensic Workflow](#recommended-forensic-workflow)
   - [Complementary Tools](#complementary-tools)

2. [iOS Forensics](#ios-forensics)
   - [First Response Procedures](#first-response-procedures)
   - [iOS Security Architecture](#ios-security-architecture)
   - [Device & Chip Compatibility Matrix](#device--chip-compatibility-matrix)
   - [Acquisition Methods](#acquisition-methods)
   - [Software Tools](#software-tools)
   - [Key iOS Databases](#key-ios-databases)
   - [Recovering Deleted Data](#recovering-deleted-data)
   - [Building a Timeline](#building-a-timeline)
   - [Reporting and Chain of Custody](#reporting-and-chain-of-custody)
   - [Quick Reference](#quick-reference)

---

# Android Forensics (ADB)

## What is ADB?

ADB (Android Debug Bridge) is a command-line tool that lets you communicate with Android devices from a computer. It is part of the Android SDK Platform Tools and is widely used in development, debugging, and digital forensics.

---

## Installation

### Windows

1. Download Platform Tools from: https://developer.android.com/tools/releases/platform-tools
2. Extract the ZIP to a permanent location like `C:\platform-tools\`
3. Add to PATH:
   - Open *System Properties → Advanced → Environment Variables*
   - Under *System Variables*, find `Path` → click *Edit*
   - Add `C:\platform-tools\`
   - Click OK and restart any open terminals
4. Verify:

```
adb version
```

### macOS

Using Homebrew (recommended):

```bash
brew install android-platform-tools
```

Or manually download, extract, and add to `~/.zshrc` or `~/.bash_profile`:

```bash
export PATH=$PATH:~/platform-tools
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install adb
```

Or manually:

```bash
unzip platform-tools-latest-linux.zip
export PATH=$PATH:~/platform-tools
```

---

## Connecting Your Phone

### Step 1 — Enable Developer Options

1. Go to **Settings → About Phone**
2. Tap **Build Number** 7 times rapidly
3. You will see *"You are now a developer!"*

### Step 2 — Enable USB Debugging

1. Go to **Settings → Developer Options**
2. Toggle **USB Debugging** ON
3. Optionally enable **Wireless Debugging** for Wi-Fi connection

### Step 3 — Connect via USB

Plug the phone in. On the phone, tap **Allow** when prompted for USB debugging.

### Step 4 — Verify Connection

```bash
adb devices
```

Expected output:

```
List of devices attached
R5CW301XXXX    device
```

If it says `unauthorized`, check the phone screen for the permission prompt.

### Wireless Connection

**Android 10 and below (USB first, then wireless):**

```bash
adb tcpip 5555
adb connect 192.168.1.XXX:5555
adb devices
```

**Android 11+ (Wireless Debugging):**

1. Go to **Developer Options → Wireless Debugging**
2. Tap *Pair device with pairing code*
3. Note the IP, port, and pairing code

```bash
adb pair 192.168.1.XXX:PAIR_PORT
# Enter the pairing code when prompted
adb connect 192.168.1.XXX:DEBUG_PORT
```

---

## Device Identification & Enumeration

Before collecting evidence, document the device:

```bash
# List connected devices
adb devices -l

# Model, manufacturer, Android version
adb shell getprop ro.product.model
adb shell getprop ro.product.manufacturer
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk

# Serial number
adb shell getprop ro.serialno

# IMEI (requires root or carrier unlock)
adb shell service call iphonesubinfo 1

# All device properties (very detailed)
adb shell getprop
```

---

## Logical Data Acquisition

```bash
# Pull a specific directory
adb pull /sdcard/DCIM/ ./evidence/photos/

# Pull entire external storage
adb pull /sdcard/ ./evidence/sdcard/

# Pull app data (requires root)
adb pull /data/data/ ./evidence/appdata/

# Full backup (no root needed — may be restricted)
adb backup -all -apk -shared -f full_backup.ab
```

**Convert `.ab` backup to readable format:**

```bash
java -jar abe.jar unpack full_backup.ab full_backup.tar
tar -xvf full_backup.tar
```

---

## File System Browsing

```bash
# Open a shell on the device
adb shell

# List files in key directories
adb shell ls /sdcard/
adb shell ls /data/data/          # App private data (root needed)
adb shell ls /system/

# Find recently modified files
adb shell find /sdcard -newer /sdcard/DCIM -type f

# Search for specific file types
adb shell find /sdcard -name "*.jpg"
adb shell find /sdcard -name "*.db"
```

---

## Extracting SQLite Databases

Most Android apps store data (messages, contacts, history) in SQLite databases:

```bash
# WhatsApp database
adb pull /sdcard/Android/media/com.whatsapp/WhatsApp/Databases/ ./evidence/whatsapp/

# SMS database (root required)
adb pull /data/data/com.android.providers.telephony/databases/mmssms.db ./evidence/

# Chrome browser history (root required)
adb pull /data/data/com.android.chrome/app_chrome/Default/History ./evidence/

# Contacts database
adb pull /data/data/com.android.providers.contacts/databases/contacts2.db ./evidence/
```

**Query locally with SQLite:**

```bash
sqlite3 mmssms.db "SELECT address, body, date FROM sms;"
sqlite3 contacts2.db "SELECT display_name, number FROM raw_contacts;"
```

---

## Live Evidence Commands

```bash
# List running processes
adb shell ps -A

# Show network connections
adb shell netstat

# Show installed packages
adb shell pm list packages

# Show installed packages with paths
adb shell pm list packages -f

# Get info about a specific app
adb shell dumpsys package com.whatsapp

# View call log
adb shell content query --uri content://call_log/calls

# View SMS inbox
adb shell content query --uri content://sms/inbox

# View contacts
adb shell content query --uri content://contacts/phones/
```

---

## Screen & Activity Capture

```bash
# Screenshot
adb shell screencap -p /sdcard/screenshot.png
adb pull /sdcard/screenshot.png ./evidence/

# Screen record (up to 3 minutes — press Ctrl+C to stop)
adb shell screenrecord /sdcard/screen_record.mp4
adb pull /sdcard/screen_record.mp4 ./evidence/

# Dump current UI state
adb shell uiautomator dump /sdcard/ui_dump.xml
adb pull /sdcard/ui_dump.xml
```

---

## Logcat (System & App Logs)

```bash
# Capture all logs
adb logcat > device_logs.txt

# Filter by tag
adb logcat -s ActivityManager

# Filter by priority (E=error, W=warning, I=info, D=debug)
adb logcat *:E

# Capture crash logs
adb logcat -b crash

# Dump existing log buffer and exit
adb logcat -d > log_dump.txt
```

---

## Physical Acquisition (Root Required)

```bash
# Get root shell
adb shell su

# Create a raw image of the data partition
dd if=/dev/block/mmcblk0p21 of=/sdcard/data_partition.img bs=4096

# Pull the image to your computer
adb pull /sdcard/data_partition.img ./evidence/
```

The image can then be analysed with tools like Autopsy, FTK, or Sleuth Kit.

---

## Useful Forensic Utilities

```bash
# Battery stats and usage
adb shell dumpsys battery
adb shell dumpsys batterystats

# Wi-Fi connection history
adb shell dumpsys wifi | grep "Recent"

# GPS/Location history
adb shell dumpsys location

# Account information
adb shell dumpsys account

# Check encryption status
adb shell getprop ro.crypto.state

# Check if device is rooted
adb shell which su
```

---

## Recommended Forensic Workflow

1. **Document** — photograph the device, note time/date, battery level, connectivity
2. **Isolate** — put device in airplane mode (or Faraday bag) to prevent remote wipe
3. **Identify** — run `getprop` commands to record device details
4. **Acquire** — pull files, databases, and logs methodically
5. **Hash** — generate MD5/SHA256 hashes of all collected files for chain of custody
6. **Analyse** — use tools like Autopsy, Cellebrite, Oxygen Forensics, or manual SQLite queries
7. **Document again** — record every command run and every file pulled

```bash
# Hash files for integrity verification
md5sum evidence/mmssms.db
sha256sum evidence/mmssms.db
```

---

## Complementary Tools

| Tool | Purpose |
|---|---|
| **Autopsy** | Full forensic analysis of pulled disk images |
| **Cellebrite UFED** | Commercial mobile forensics suite |
| **Oxygen Forensic Detective** | App data and cloud extraction |
| **Magnet AXIOM** | Artifact parsing and timeline building |
| **SQLite Browser** | GUI for viewing pulled `.db` files |
| **Wireshark** | Analyse network traffic alongside ADB |

---

---

# iOS Forensics

> iOS forensics is considered the most challenging domain in mobile forensics. Apple's vertically integrated hardware-software ecosystem and aggressive privacy stance means investigators face multiple layers of protection at every step.

---

## First Response Procedures

### Scene Documentation

Before touching the device, document everything:

- Photograph the device in its found position
- Note whether the screen is on or off and the battery level if visible
- Record physical condition (damage, accessories connected)
- Note environment (near Faraday bag, signal blocker, or charging?)
- Record exact time and date of seizure in **UTC**

### Network Isolation — CRITICAL

A remote wipe via **Find My iPhone** can destroy all evidence in seconds.

**Option A — Airplane Mode (if screen is accessible):**
- Enable Airplane Mode via Control Centre
- Also disable Wi-Fi and Bluetooth manually (they can re-enable after Airplane Mode on newer iOS)
- Turn off Location Services

**Option B — Faraday Bag (most reliable):**
- Place device directly into an RF-shielding Faraday bag
- Blocks all cellular, Wi-Fi, Bluetooth, and GPS signals
- Keep the device powered and charging inside the bag via a Faraday-compatible port

> ⚠️ **Never turn the device off** unless absolutely necessary. Powering off an iPhone with an unknown passcode can lock you out permanently — after a reboot, iOS requires the passcode before biometrics work (**BFU state**).

### BFU vs AFU — Critical Concept

| State | Full Name | Meaning | Data Accessible |
|---|---|---|---|
| **BFU** | Before First Unlock | Device rebooted, passcode never entered since boot | Almost nothing — all encryption keys destroyed |
| **AFU** | After First Unlock | Passcode entered at least once since last boot | Most data accessible with the right tools |

If you find the phone already unlocked — **do not let it reboot**. Keep it powered in AFU state.

---

## iOS Security Architecture

### Hardware Security

**Secure Enclave Processor (SEP)**
- Dedicated coprocessor in every iPhone since 5s
- Manages all cryptographic operations
- Stores the device's unique ID (UID key) — never exposed to the main CPU
- Enforces PIN attempt limits and handles Face ID / Touch ID matching
- Cannot be accessed by any software, even with root

**UID Key** — A unique 256-bit AES key burned into silicon at manufacture. Never leaves the Secure Enclave. All file encryption ultimately derives from this key combined with the user's passcode.

**GID Key** — A group key shared by all devices with the same chip. Used only for decrypting firmware, not user data.

### File System Encryption — iOS Data Protection

iOS uses a four-class encryption model. Every file belongs to one of these classes:

| Class | Name | When Accessible | Used For |
|---|---|---|---|
| A | Complete Protection | Only when unlocked | Most sensitive app data |
| B | Protected Unless Open | Unlocked, or file already open | Mail attachments, downloads |
| C | Protected Until First Auth | After first unlock (AFU) | Most user data |
| D | No Protection | Always | Internal OS files |

This is why AFU vs BFU matters so much — in AFU, Class C files (the majority of user data) are decryptable.

### Secure Boot Chain

Every component of the iOS boot process is cryptographically signed by Apple:
- Unsigned code cannot run during boot
- Downgrades to older iOS versions are blocked once Apple stops signing them
- Custom boot environments are impossible on modern devices without a hardware exploit

### The Passcode Problem

| Scenario | Result |
|---|---|
| **Without passcode** | Class A and C file keys cannot be derived; Secure Enclave erases keys after 10 failed attempts |
| **With passcode** | Full file system extraction possible; all protection classes become accessible |

No software tool can bypass this on modern devices (A12+).

---

## Device & Chip Compatibility Matrix

| Device | Chip | Checkm8 | Full FS (with passcode) | BFU Extraction |
|---|---|---|---|---|
| iPhone 5s | A7 | ✅ Yes | ✅ Yes | Partial |
| iPhone 6 / 6 Plus | A8 | ✅ Yes | ✅ Yes | Partial |
| iPhone 6s / SE (1st) | A9 | ✅ Yes | ✅ Yes | Partial |
| iPhone 7 / 7 Plus | A10 | ✅ Yes | ✅ Yes | Partial |
| iPhone 8 / X | A11 | ✅ Yes | ✅ Yes | Partial |
| iPhone XS / XR / 11 series | A12/A13 | ❌ No | ✅ Yes (passcode needed) | Very limited |
| iPhone 12 series | A14 | ❌ No | ✅ Yes (passcode needed) | Very limited |
| iPhone 13 series | A15 | ❌ No | ✅ Yes (passcode needed) | Very limited |
| iPhone 14 series | A15/A16 | ❌ No | Limited | Almost none |
| iPhone 15 / 16 series | A17/A18 | ❌ No | Limited | Almost none |

---

## Acquisition Methods

### 4.1 Manual Acquisition

Simply photographing or recording the screen — no tools needed.

**When to use:** Device is unlocked and other methods are unavailable or time is critical.

**Limitations:** Extremely slow, incomplete, no metadata captured, not forensically sound.

---

### 4.2 iCloud Acquisition

If you have the Apple ID and password (or legal authority), iCloud is often the richest source.

**What iCloud may contain:**
- iMessage and SMS history (if Messages in iCloud is enabled)
- Photos and videos (full resolution)
- Contacts, Calendar, Notes, Reminders
- App data for iCloud-enabled apps
- Safari history and bookmarks
- Health data
- Device backups (last 3, up to 180 days old)
- Location history
- Mail (if using iCloud Mail)

**Tools that support iCloud extraction:**
- Cellebrite UFED Cloud Analyzer
- Oxygen Forensic Detective (Cloud module)
- Magnet AXIOM (Cloud module)
- iMazing (consumer tool, limited forensic use)

**Legal process to Apple:**
Apple responds to search warrants, court orders, and emergency requests. Apple can provide iCloud backup contents, Drive files, Photos, Mail, Contacts, and more — but **not** end-to-end encrypted data if the user has enabled **Advanced Data Protection (ADP)**.

> ⚠️ **ADP (iOS 16.2+):** If enabled, end-to-end encryption is extended to almost all iCloud categories including backups. Even Apple cannot decrypt this data.

---

### 4.3 iTunes / Local Backup Acquisition

If the device has previously synced with a computer, a local backup may be accessible.

**Backup locations:**

- Windows: `C:\Users\[username]\AppData\Roaming\Apple Computer\MobileSync\Backup\`
- macOS: `~/Library/Application Support/MobileSync/Backup/`

**Backup types:**

| Type | Encrypted | Contents |
|---|---|---|
| Unencrypted | No | Most app data, no passwords/Health |
| Encrypted | Yes (user password) | Everything including passwords, Health, Wi-Fi credentials |

**Creating a forensic backup using libimobiledevice:**

```bash
idevicebackup2 backup --full /path/to/evidence/backup/

# Check device info first
ideviceinfo
ideviceid -l
```

**Backup file structure:**
iOS backups are stored as a flat directory of files renamed to their SHA1 hash. The `Manifest.db` SQLite database maps hashes to original file paths:

```bash
sqlite3 Manifest.db "SELECT fileID, relativePath FROM Files WHERE relativePath LIKE '%sms%';"
```

**Tools for backup analysis:**
- iBackup Viewer — GUI, free, quick browsing
- iPhone Backup Extractor — commercial, thorough
- Oxygen Forensic Detective — professional, parses hundreds of apps
- Autopsy with iOS plugin — free, open source
- APOLLO — free Python tool, analyses activity patterns

---

### 4.4 Logical Acquisition via AFC

**AFC (Apple File Conduit)** is Apple's file transfer protocol. In a trusted (paired) connection, it exposes the media portion of the file system.

```bash
# Mount device filesystem via AFC
ifuse /mnt/ios_device/

# List contents
ls /mnt/ios_device/

# Copy photos
cp -r /mnt/ios_device/DCIM/ /evidence/photos/
```

This only reaches the media partition, not app sandboxes or system data.

---

### 4.5 Full File System Extraction

The most valuable acquisition method — a complete copy of the entire file system.

**Requires:** Either the device passcode + a supported tool, or a jailbreak exploit.

#### Method A — Checkm8 / Checkra1n (A11 and older)

**Checkm8** is a hardware bootrom vulnerability (discovered 2019 by axi0mX). Because it exists in read-only hardware, it can never be patched by Apple. It affects all devices with Apple A5 through A11 chips.

**Forensic tools using Checkm8:**
- Cellebrite UFED (Checkm8 extraction mode)
- Elcomsoft iOS Forensic Toolkit (EIFT)
- Magnet AXIOM (via Checkm8)
- checkra1n (open source jailbreak)

**Process using EIFT:**

```
1. Connect iPhone via USB
2. Boot device into DFU mode:
   - iPhone 8 and earlier: Hold Home + Power → release Power → hold Home
   - iPhone X and later (A11): Hold Side + Vol Down → release Side → hold Vol Down
3. EIFT exploits the bootrom vulnerability
4. A forensic agent is temporarily booted (never written to device storage)
5. Full file system is streamed to the examiner's computer
6. Device reboots cleanly — no permanent modification
```

**What Checkm8 extraction gives you:**
- Complete `/private/var/` (all user data)
- Complete `/private/var/mobile/` (all app sandboxes)
- Keychain (passwords, tokens, certificates)
- Location history, Health and fitness data
- All SQLite databases unencrypted
- Deleted file remnants (in unallocated space)

#### Method B — Agent-Based Extraction (A12+ with passcode)

For modern devices where Checkm8 doesn't apply, commercial tools deploy a signed **forensic agent** onto the device using enterprise certificates.

- Requires the device to be unlocked and trusted
- Does not give the same depth as Checkm8 but significantly more than a logical backup

Tools: Cellebrite UFED, Magnet AXIOM, Oxygen Forensic Detective

#### Method C — GrayKey (Law Enforcement Only)

Dedicated hardware by Grayshift used by law enforcement:
- Exploits undisclosed iOS vulnerabilities to bypass the passcode attempt limit
- Performs brute-force passcode cracking (6-digit PIN in hours to days)
- Provides full file system extraction after cracking
- Updated regularly to support newest iOS versions
- Costs tens of thousands of dollars — restricted to verified law enforcement

---

### 4.6 Physical Acquisition

**JTAG** — Connecting directly to test access points on the circuit board. Rarely applicable to iPhones as Apple does not expose standard JTAG interfaces.

**Chip-off** — Physically removing the NAND flash chip and reading it with specialised hardware. Even if successful, data is encrypted at the hardware level via the UID key in the Secure Enclave — making chip-off largely useless on iPhone 5s and later.

---

## Software Tools

### Commercial Tools

| Tool | Key Features | Cost |
|---|---|---|
| **Cellebrite UFED** | Industry standard; supports 25,000+ devices; physical, logical, file system, cloud extraction; Checkm8 mode | $5,000–$15,000+/year |
| **Magnet AXIOM** | Cloud + app parsing; timeline view; AI-powered media categorisation; 500+ app artefacts | Commercial licence |
| **Oxygen Forensic Detective** | Outstanding app/cloud parsing; drone, vehicle, IoT support; 80+ cloud services | Commercial licence |
| **Elcomsoft iOS Forensic Toolkit** | Most granular control; Checkm8 exploitation; Keychain extraction | $1,500–$4,000 |
| **Elcomsoft Phone Breaker** | Encrypted backup decryption; iCloud acquisition; extracts iCloud tokens from synced computers | ~$200–$1,500 |

### Open Source & Free Tools

**libimobiledevice** — Foundational open-source library for communicating with iOS devices:

```bash
# Install on Ubuntu
sudo apt install libimobiledevice-utils

# Install on macOS
brew install libimobiledevice

# Key commands
ideviceinfo          # Device information
ideviceid            # Get device UDID
idevicebackup2       # Create/restore backups
idevicescreenshot    # Take screenshots
idevicesyslog        # Stream device syslog
ifuse                # Mount device as filesystem
```

**checkra1n** — Open-source jailbreak based on Checkm8 (A5–A11 devices):

```bash
./checkra1n -c          # CLI mode
./checkra1n --verbose   # Verbose output
```

**iLEAPP (iOS Logs, Events, and Plists Parser)** — Free Python tool by Alexis Brignoni:

```bash
pip install ileapp
python ileapp.py -t fs -i /path/to/extracted_fs/ -o /path/to/output/
```

Parses location history, app usage, Bluetooth devices, Wi-Fi networks, health data, notifications, browser history. Outputs a clean HTML report.

**APOLLO (Apple Pattern of Life Lazy Output'er)** — Created by Sarah Edwards. Builds a timeline of user activity:

```bash
git clone https://github.com/mac4n6/APOLLO
python apollo.py -o /output/ -m modules/ /path/to/extracted_db_files/
```

**Autopsy** — Free open-source digital forensics platform with iOS backup support.

**DB Browser for SQLite** — Essential free tool for manually examining extracted `.db` files.

**Bulk Extractor** — Carves data from raw images without parsing the file system:

```bash
bulk_extractor -o /output/ /path/to/ios_image.dmg
```

---

## Key iOS Databases

### Communications

```
SMS / iMessage:
/private/var/mobile/Library/SMS/sms.db
→ Tables: message, chat, handle, attachment

Call History:
/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata
→ Table: ZCALLRECORD (date, duration, number, FaceTime y/n)

Voicemail:
/private/var/mobile/Library/Voicemail/voicemail.db
```

**Querying the SMS database:**

```sql
SELECT 
    datetime(message.date/1000000000 + strftime('%s','2001-01-01'), 'unixepoch') as date,
    handle.id as contact,
    message.text,
    message.is_from_me
FROM message
JOIN handle ON message.handle_id = handle.rowid
ORDER BY message.date;
```

### Location Data

```
Significant Locations:
/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite
/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite

Maps search history:
/private/var/mobile/Library/Maps/GeoHistory.mapsdata

Location Services usage by app:
/private/var/mobile/Library/LocationD/clients.plist
```

### Device Activity

```
App usage / Screen time:
/private/var/mobile/Library/Application Support/com.apple.remotemanagementd/RMAdminStore-Local.sqlite

Notifications history:
/private/var/mobile/Library/UserNotifications/[UUID]/store.sqlite3

Photos metadata:
/private/var/mobile/Media/PhotoData/Photos.sqlite
→ Contains GPS coordinates, timestamps, EXIF data for every photo
```

### Accounts and Credentials

```
Keychain (requires Checkm8 or root):
/private/var/Keychains/keychain-2.db
→ Contains: Wi-Fi passwords, app passwords, auth tokens, certificates

Apple ID accounts:
/private/var/mobile/Library/Accounts/Accounts3.sqlite

Known Wi-Fi networks:
/private/var/preferences/com.apple.wifi.known-networks.plist
```

### Third-Party Apps

```
WhatsApp:
/private/var/mobile/Containers/Shared/AppGroup/[UUID]/ChatStorage.sqlite

Telegram:
/private/var/mobile/Containers/Data/Application/[UUID]/Documents/

Signal:
/private/var/mobile/Containers/Data/Application/[UUID]/Documents/database/signal.sqlite
(encrypted with SQLCipher — requires key extraction)

Snapchat:
/private/var/mobile/Containers/Data/Application/[UUID]/Library/Caches/

Chrome:
/private/var/mobile/Containers/Data/Application/[UUID]/Documents/ChromeProfile/History
```

---

## Recovering Deleted Data

### How Deletion Works on iOS

- SQLite databases mark rows as deleted but keep them in **free pages** until overwritten
- Files are removed from directory entries but data blocks may persist until overwritten
- APFS uses **copy-on-write** — old versions of data can persist in unallocated space

### Recovery Methods

**SQLite WAL (Write-Ahead Log) Analysis**

The WAL file (`.db-wal`) contains recent uncommitted transactions and often holds deleted records:

```bash
# WAL sits alongside the database
ls -la /path/to/sms.db*
# sms.db  sms.db-wal  sms.db-shm
```

**SQLite Free Page Carving**

Tools like SQLite Forensic Explorer and Oxygen Forensic Detective carve deleted rows from SQLite free pages.

**File Carving from Raw Image**

```bash
# Using Foremost
foremost -i ios_filesystem.dmg -o /output/ -t jpg,png,mov,mp4,pdf

# Using PhotoRec
photorec ios_filesystem.dmg
```

**APFS Snapshot Analysis**

If APFS snapshots exist, they can contain older versions of files since deleted:

```bash
tmutil listlocalsnapshotdates
```

---

## Building a Timeline

### Key Timestamp Sources on iOS

- File system MAC times (Modified, Accessed, Changed)
- SQLite database timestamps (often stored as Cocoa timestamps: seconds since 2001-01-01)
- EXIF metadata in photos and videos
- App-specific timestamps in plist files
- Notification, location, and iCloud sync timestamps

### Converting iOS (Cocoa) Timestamps

iOS timestamps are seconds since January 1, 2001:

```python
import datetime

def cocoa_to_datetime(cocoa_timestamp):
    cocoa_epoch = datetime.datetime(2001, 1, 1)
    return cocoa_epoch + datetime.timedelta(seconds=cocoa_timestamp)

print(cocoa_to_datetime(715000000))
```

### Timeline Tools

**log2timeline / Plaso:**

```bash
# Extract all timeline artefacts from iOS backup
log2timeline.py --parsers ios_backup ios_timeline.plaso /path/to/backup/

# Filter and export to CSV
psort.py -o l2tcsv -w timeline.csv ios_timeline.plaso
```

- **AXIOM Timeline** — built into Magnet AXIOM, visual and filterable
- **iLEAPP** — outputs a timeline view in its HTML report automatically

---

## Reporting and Chain of Custody

### Hashing — Integrity Verification

```bash
# Hash the extracted image
md5sum ios_filesystem.dmg > ios_filesystem.md5
sha256sum ios_filesystem.dmg > ios_filesystem.sha256

# Verify later
sha256sum -c ios_filesystem.sha256
```

### Chain of Custody Documentation

Record every action taken including:

- Who seized the device, when, and where
- Device state at seizure (on/off, locked/unlocked, battery %)
- Every tool used with version number
- Every command run with timestamp
- Who had custody at every point
- Storage conditions (Faraday bag, evidence locker)
- Hash values of all acquired images

### Report Structure

1. **Executive Summary** — non-technical overview of findings
2. **Examiner Qualifications** — certifications, experience
3. **Evidence Received** — device description, serial, IMEI, condition
4. **Tools Used** — name, version, validation status
5. **Methodology** — acquisition method chosen and why
6. **Findings** — detailed artefact analysis with screenshots
7. **Timeline** — chronological reconstruction of events
8. **Conclusions** — factual, not speculative
9. **Appendices** — raw data, hash values, tool logs

---

## Quick Reference

### Acquisition Decision Tree

```
Device found → Is it on?
    ├── NO → Do NOT power on if passcode unknown
    │         Use Checkm8 if A11 or older
    │         Consider chip-off (data will be encrypted)
    │
    └── YES → Is it unlocked / in AFU state?
                ├── YES → Connect immediately, trust device
                │          Use Cellebrite/AXIOM/EIFT for full FS
                │
                └── NO → Is it A11 or older?
                            ├── YES → Use Checkm8 (passcode not needed)
                            └── NO → Need passcode
                                      ├── Known → Full FS via commercial tool
                                      └── Unknown → GrayKey (LE only)
                                                     iCloud if credentials available
                                                     Legal process to Apple
```

### Certification Paths for iOS Forensics

| Certification | Body | Focus |
|---|---|---|
| **CCME** | Cellebrite | Cellebrite tool proficiency |
| **CFCE** | IACIS | General digital forensics |
| **CCE** | ISFCE | Certified Computer Examiner |
| **GCFE** | GIAC | Enterprise forensics |
| **EnCE** | OpenText | EnCase platform |
| **MCFE** | MSAB | Mobile forensics |

---

> iOS forensics is a constantly evolving field. Apple releases new iOS versions and security patches regularly, and forensic tool vendors race to keep up. Staying current requires ongoing training, tool updates, and engagement with the forensic research community.
