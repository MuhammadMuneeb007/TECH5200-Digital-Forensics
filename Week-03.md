# Digital Forensics Investigation: Case Study
## *Operation DataBreach — NovaTech Solutions Pty Ltd*

> **Document Type:** Educational Case Study — Hypothetical Scenario  
> **Purpose:** GitHub Repository Resource — Digital Forensics Investigations  
> **Audience:** Students and practitioners learning the end-to-end forensic investigation process  
> **Scenario Based On:** Real-world insider threat investigations; fictional company, people, and events  

---

## Table of Contents

1. [Case Overview](#1-case-overview)
2. [Phase 1 — Identification](#2-phase-1--identification)
3. [Phase 2 — Preservation](#3-phase-2--preservation)
4. [Phase 3 — Collection](#4-phase-3--collection)
5. [Phase 4 — Examination](#5-phase-4--examination)
6. [Phase 5 — Analysis](#6-phase-5--analysis)
7. [Phase 6 — Documentation](#7-phase-6--documentation)
8. [Phase 7 — Presentation](#8-phase-7--presentation)
9. [Phase 8 — Review](#9-phase-8--review)
10. [Phase 9 — Closure](#10-phase-9--closure)
11. [Appendix A — Tools Reference](#appendix-a--tools-reference)
12. [Appendix B — Laws and Regulations](#appendix-b--laws-and-regulations)
13. [Appendix C — Chain of Custody Template](#appendix-c--chain-of-custody-template)
14. [References](#references)

---

## 1. Case Overview

### Background

**NovaTech Solutions Pty Ltd** is a Brisbane-based software company with 120 employees that develops proprietary asset management software for the mining sector. On **10 March 2026**, the Head of IT Security, **Michael Okonkwo**, flagged an anomaly to senior management: the Data Loss Prevention (DLP) system generated an alert showing that a large volume of files from the `\\FILESERVER01\Projects\` directory had been accessed and potentially copied by user account `jthompson` between **22:00 and 23:45 on 9 March 2026** — outside of normal business hours.

**James Thompson**, a Senior Software Engineer, had resigned effective **13 March 2026** and was serving his notice period. Management suspected he may have exfiltrated proprietary source code and client data before leaving.

The company's legal counsel engaged **CyberTrace Forensics**, a licensed digital forensics firm, to conduct an independent investigation. Lead Investigator **Dr. Amara Singh** (CFCE, EnCE) led the engagement.

### Goals vs. Objectives

| | Detail |
|---|---|
| **Goal** | Determine whether company intellectual property was stolen and by whom |
| **Objective 1** | Identify whether files were accessed outside of normal hours |
| **Objective 2** | Determine whether files were copied to an external medium |
| **Objective 3** | Establish a timeline of events between 9–16 March 2026 |
| **Objective 4** | Identify the user account and device responsible |
| **Objective 5** | Determine how any data left the corporate network |
| **Objective 6** | Produce court-admissible evidence and a forensic report |

### Scope

| Scope Item | Detail |
|---|---|
| **Devices** | Office desktop PC (`NOVA-WS-047`), company-issued laptop (`NOVA-LT-019`), USB drive recovered from desk drawer |
| **Data Sources** | Windows Event Logs, Active Directory logs, DLP system logs, email server logs, USB device history |
| **Network Sources** | Firewall logs, proxy server logs, cloud storage access logs (OneDrive, SharePoint) |
| **Time Window** | 10 March 2026 to 16 March 2026 (investigation period); 9 March 2026 22:00–23:45 (incident window) |
| **Systems** | Company-owned assets only; personal devices excluded unless voluntarily surrendered |
| **Out of Scope** | Personal mobile phone, personal email accounts, home network |

### Legal Authority

The investigation was authorised under:
- Written consent from NovaTech Solutions Pty Ltd as device owner (all assets are company property per the employment agreement)
- Reference to **Section 477.1 of the Criminal Code Act 1995 (Cth)** — Unauthorised access to, or modification of, restricted data
- Reference to **Section 478.1 of the Criminal Code Act 1995 (Cth)** — Unauthorised impairment of data
- NovaTech's **Acceptable Use Policy (AUP)** and **IT Security Policy**, both signed by James Thompson on commencement
- Engagement letter and Memorandum of Understanding between NovaTech Legal and CyberTrace Forensics, dated 11 March 2026

> **Important:** No law enforcement warrant was issued at this stage. This was a civil/corporate investigation. Any referral to the Australian Federal Police (AFP) would require separate authorisation.  
> See: [Australian Criminal Code Act 1995](https://www.legislation.gov.au/Details/C2021C00183)

---

## 2. Phase 1 — Identification

> **Purpose:** Identify potential sources of evidence, establish what happened, and define the scope and objectives of the investigation.

### 2.1 Initial Notification

On **10 March 2026 at 08:15 AEST**, Michael Okonkwo emailed NovaTech's legal counsel and IT Manager with the DLP alert. The alert described:

- **User:** `NOVATECH\jthompson`
- **Source Host:** `NOVA-WS-047`
- **Files Accessed:** 847 files in `\\FILESERVER01\Projects\AssetPro_v4\`
- **Time:** 9 March 2026, 22:03–23:47
- **Alert Trigger:** Volume threshold exceeded (>500 files in 60 minutes) + access outside business hours

CyberTrace Forensics was contacted by 10:00 AEST and dispatched Dr. Amara Singh and Digital Forensic Technician **Priya Nair** to the NovaTech premises.

### 2.2 Scene Assessment

Upon arrival at **NovaTech offices, Level 4, 123 Eagle Street, Brisbane QLD 4000** at 13:30 AEST, the investigators:

1. Met with Michael Okonkwo (IT Head), Elena Marchetti (General Manager), and David Yu (Legal Counsel)
2. Reviewed the physical workspace of James Thompson — Desk 14, Open Plan, Floor 4
3. Photographed the workspace before touching anything

**Potential evidence identified:**

| Item | Description | Location |
|---|---|---|
| **E-001** | Desktop PC — Dell OptiPlex 7090 | Desk 14, powered off |
| **E-002** | Company laptop — Lenovo ThinkPad T490 | Desk 14, lid closed, possibly in sleep mode |
| **E-003** | 32 GB USB drive (SanDisk, black casing) | Desk drawer, unlocked |
| **E-004** | DLP system alert logs | IT server room, `NOVA-DLP-01` |
| **E-005** | Active Directory / Windows Event Logs | Domain controller `NOVA-DC-01` |
| **E-006** | Email server logs | Exchange Server `NOVA-MAIL-01` |
| **E-007** | Firewall / proxy logs | Palo Alto Networks firewall, rack unit 3 |

### 2.3 Preliminary Findings

- The laptop (E-002) was warm to the touch, suggesting it was recently used or still in sleep mode — **volatile memory may be present and recoverable**
- The USB drive (E-003) was unlabelled with no asset tag — **not registered in IT asset register**, suggesting it was personally brought in
- DLP logs confirmed that `jthompson` accessed the file server at 22:03, which was captured under Event ID 4624 (Logon) and 4663 (Object Access) in Windows Security Event Logs

### 2.4 Legal and Ethical Checks

Before proceeding, the team confirmed:

- [x] Written authorisation obtained from device owner (NovaTech)
- [x] No active law enforcement warrant that would transfer jurisdiction
- [x] Subject (James Thompson) was not present — no self-incrimination concerns at this stage
- [x] Privacy Act 1988 (Cth) considered — investigation limited to company-owned systems
- [x] Australian Privacy Principle 11 (security of personal information) acknowledged — personal employee data to be handled with minimum necessary access

> **Reference:** [Privacy Act 1988 (Cth)](https://www.legislation.gov.au/Details/C2022C00199)

---

## 3. Phase 2 — Preservation

> **Purpose:** Protect the evidence from alteration, contamination, or loss. Establish and maintain the chain of custody.

### 3.1 Actions Taken

**Time: 14:00 AEST, 10 March 2026**

#### Desktop PC (E-001) — Powered Off

- Photographed front, back, and all ports
- Verified system was powered off — no volatile memory acquisition needed
- Affixed tamper-evident evidence seal over power button
- Documented serial number: `CNX123456789`
- Placed in antistatic evidence bag, sealed with red evidence tape
- Recorded in Evidence Log

#### Laptop (E-002) — Sleep State

> ⚠️ **Critical decision:** The laptop was in sleep mode. Shutting it down would lose volatile RAM contents. Live acquisition was performed first.

- Connected external forensic drive (Tableau TX1, write-protected)
- Used **Magnet RAM Capture v1.2** to dump 16 GB RAM to forensic drive
- RAM capture MD5 hash recorded immediately: `a3f4b2c1...`
- System then gracefully shut down via Start → Shutdown to minimise OS writes
- Affixed tamper-evident seal, placed in antistatic bag
- Serial number: `PF2ABCDE`

#### USB Drive (E-003)

- Photographed in situ before touching
- Picked up with nitrile gloves (in case physical forensics are later required)
- Inserted into **Tableau T8-R2 USB write-blocker** to verify connection without writes
- Placed in anti-static evidence bag, heat-sealed
- Serial number from device: `4C530000...` (USB serial read via write-blocker)

#### Server Logs (E-004 to E-007)

- IT Manager Michael Okonkwo provided read-only access credentials for log export
- Logs were **not touched on live systems** — copies exported to forensic drive via PowerShell
- All exported log files hashed with SHA-256 immediately upon export

### 3.2 Write Blockers Used

| Device | Write Blocker | Purpose |
|---|---|---|
| Desktop HDD | **Tableau T35689iu** (SATA/IDE) | Prevent writes during imaging |
| Laptop SSD | **Tableau T8-R2** (USB 3.0) | Prevent writes during imaging |
| USB Drive | **Tableau T8-R2** | Prevent writes during preview |

> **Why write blockers?** Without a write blocker, simply connecting a drive to a forensic workstation causes the OS to write access timestamps and metadata, altering the evidence. Write blockers are hardware/software devices that permit read commands while intercepting and blocking all write commands.
>
> **Reference:** NIST SP 800-101 Rev. 1 — Guidelines on Mobile Device Forensics (principle applies broadly to all digital media) — [https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final](https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final)

### 3.3 Chain of Custody Log

All items were logged in the **Evidence Register** (ERF-2026-031) maintained by Priya Nair:

| Evidence ID | Description | Collected By | Time | Location Stored | Seal # |
|---|---|---|---|---|---|
| E-001 | Dell Desktop PC | Dr. A. Singh | 14:10 | Locked evidence room, Brisbane CBD Police Station (by arrangement) | EV-9201 |
| E-002 | Lenovo Laptop | Priya Nair | 14:35 | As above | EV-9202 |
| E-003 | 32 GB USB drive | Dr. A. Singh | 14:20 | As above | EV-9203 |
| E-004 | DLP log export (digital) | Priya Nair | 15:00 | Encrypted forensic drive, CyberTrace lab | N/A |
| E-005 | AD/Event logs (digital) | Priya Nair | 15:15 | As above | N/A |
| E-006 | Email server logs (digital) | Priya Nair | 15:20 | As above | N/A |
| E-007 | Firewall/proxy logs (digital) | Priya Nair | 15:30 | As above | N/A |

> Physical evidence (E-001 to E-003) was transported to Brisbane CBD Police Station's property storage by arrangement with Station Sergeant David Walsh, for use of their evidence storage facility under a Memorandum of Understanding with CyberTrace Forensics. This is common in corporate investigations where secure evidence storage is needed.

---

## 4. Phase 3 — Collection

> **Purpose:** Create forensically sound copies of all evidence for examination. The original evidence must not be examined directly.

### 4.1 Forensic Imaging

All imaging was performed at the **CyberTrace Forensics laboratory, 45 Mary Street, Brisbane** on **11 March 2026**, using a **Tableau Forensic Imager TD3** connected to a forensic workstation running **SIFT Workstation (v3.0)** on Ubuntu.

#### Desktop PC HDD — Seagate 1TB SATA (E-001)

```
Imaging Tool:    FTK Imager v4.7.1
Image Format:    E01 (Expert Witness Format) — compressed, with CRC verification
Source Hash:     MD5: d41d8cd9...  SHA-256: e3b0c442...
Image Hash:      MD5: d41d8cd9...  SHA-256: e3b0c442...  [MATCH ✓]
Image Location:  //FORENSIC-NAS/Cases/ERF-2026-031/E001/NOVA-WS-047-HDD.E01
Verified:        Yes — FTK Imager verified sector-by-sector match
Time Taken:      2h 14m
```

#### Laptop SSD — Samsung 512GB NVMe (E-002)

```
Imaging Tool:    FTK Imager v4.7.1
Image Format:    E01
Source Hash:     MD5: a3b7f1c9...  SHA-256: 9f2e44a1...
Image Hash:      MD5: a3b7f1c9...  SHA-256: 9f2e44a1...  [MATCH ✓]
Image Location:  //FORENSIC-NAS/Cases/ERF-2026-031/E002/NOVA-LT-019-SSD.E01
Verified:        Yes
Time Taken:      55m
```

#### USB Drive — SanDisk 32GB (E-003)

```
Imaging Tool:    FTK Imager v4.7.1
Image Format:    DD (raw image) + MD5/SHA-256 hash file
Source Hash:     MD5: ff7c3ab1...  SHA-256: 2d4a9f01...
Image Hash:      MD5: ff7c3ab1...  SHA-256: 2d4a9f01...  [MATCH ✓]
Image Location:  //FORENSIC-NAS/Cases/ERF-2026-031/E003/USB-SANDISK-32GB.dd
Verified:        Yes
Time Taken:      4m
```

> **Why hash verification?** Hash functions (MD5, SHA-256) produce a unique digital fingerprint of data. If even a single bit changes during imaging, the hash will not match. A matching hash between source and image proves the copy is forensically identical. This is critical for evidence admissibility.

### 4.2 RAM Analysis Collection (E-002)

The RAM dump captured during Preservation was already stored as a `.mem` file:

```
File:            NOVA-LT-019-RAM-20260310-1435.mem
Size:            16,384 MB
Tool:            Magnet RAM Capture v1.2
Hash:            MD5: a3f4b2c1...  SHA-256: 7c2d9e1a...
Location:        //FORENSIC-NAS/Cases/ERF-2026-031/E002/RAM/
```

### 4.3 Log File Collection

All server log exports were verified on collection:

| Log Source | Format | Lines | Hash (SHA-256) |
|---|---|---|---|
| DLP Alert Log | `.evtx` / `.csv` | 14,302 | `1a2b3c4d...` |
| Windows Security Event Log (E-005) | `.evtx` | 1,204,401 | `5e6f7a8b...` |
| Exchange Server Log | `.log` | 42,871 | `9c0d1e2f...` |
| Palo Alto Firewall Log | `.csv` | 892,304 | `3a4b5c6d...` |

---

## 5. Phase 4 — Examination

> **Purpose:** Search the collected data for artefacts relevant to the investigation. Extract and filter information without drawing conclusions yet.

### 5.1 Desktop PC (E-001) — NOVA-WS-047

**Tool used:** Autopsy v4.21.0 (open source), X-Ways Forensics v20.9

#### 5.1.1 File System Analysis

- **OS:** Windows 11 Pro, Build 22621
- **User Profile:** `C:\Users\jthompson\`
- **Last Login:** 9 March 2026, 21:58:44 (local time)
- **Last Shutdown:** 10 March 2026, 07:52:13 (by IT Manager, after DLP alert)

#### 5.1.2 USB Device History

Examiner queried the Windows Registry for USB device history:

**Registry path:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`

**Finding:** The SanDisk 32GB USB (serial: `4C530000...`) was connected to NOVA-WS-047 on:
- 9 March 2026 at **22:09:33**
- 9 March 2026 at **23:31:47** (disconnected)

> **Tool:** Registry Explorer (Eric Zimmermann) — [https://ericzimmerman.github.io](https://ericzimmerman.github.io)

#### 5.1.3 Shellbag Analysis

Shellbags record folder navigation history in the Windows Registry even for deleted folders:

**Registry path:** `HKEY_USERS\{SID}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

**Finding:** `jthompson`'s profile showed navigation to:
- `\\FILESERVER01\Projects\AssetPro_v4\Source\` at 22:04
- `E:\` (removable drive — consistent with USB) at 22:11
- `E:\AssetPro_Backup\` at 22:11 (folder name on USB)

> **Tool:** ShellBagsExplorer (Eric Zimmermann)

#### 5.1.4 Prefetch Files

Windows Prefetch files record recently run executables:

**Path:** `C:\Windows\Prefetch\`

**Relevant prefetch found:**
- `ROBOCOPY.EXE-XXXXXXXX.pf` — Last run: 9 March 2026, 22:12:01
  - Robocopy is a Windows command-line file copy tool commonly used for bulk transfers
- `7Z.EXE-XXXXXXXX.pf` — Last run: 9 March 2026, 23:15:44
  - 7-Zip, used for archiving/compressing files

#### 5.1.5 Recycle Bin

Deleted files found in `C:\$Recycle.Bin\`:
- `robocopy_transfer.log` — deleted 9 March 2026, 23:45 (matches incident window end)
  - File recovered intact using FTK Imager's recycle bin parser
  - Log confirmed copy of 847 files from `\\FILESERVER01\Projects\AssetPro_v4\` to `E:\AssetPro_Backup\`

#### 5.1.6 LNK Files (Recent Files / Jump Lists)

Windows shortcut (`.lnk`) files record recently accessed files:

**Path:** `C:\Users\jthompson\AppData\Roaming\Microsoft\Windows\Recent\`

**Findings:** LNK files pointing to:
- `E:\AssetPro_Backup\README.txt` — last accessed 23 March 2026 at 22:45 (outside office premises based on no login to domain)

---

### 5.2 Laptop (E-002) — NOVA-LT-019

#### 5.2.1 RAM Analysis

**Tool:** Volatility3 v2.5.0

```bash
# List running processes at time of capture
python3 vol.py -f NOVA-LT-019-RAM.mem windows.pslist

# Check network connections
python3 vol.py -f NOVA-LT-019-RAM.mem windows.netstat

# Dump browser history from memory
python3 vol.py -f NOVA-LT-019-RAM.mem windows.cmdline
```

**Key RAM findings:**
- At time of capture (10 March 2026, 14:35), processes running included: `chrome.exe`, `outlook.exe`, `OneDrive.exe`, `7z.exe` (background)
- Network connections showed an active HTTPS connection to `onedrive.live.com` (Microsoft OneDrive personal)
- Command line history revealed: `robocopy \\FILESERVER01\Projects\AssetPro_v4 E:\AssetPro_Backup /E /LOG:robocopy_transfer.log`

#### 5.2.2 Browser History

**Tool:** Autopsy Browser Artefact Analyser module

Significant URLs accessed from the laptop on 9 March 2026:
- `https://onedrive.live.com/upload` — 23:47 (3.4 GB file upload)
- `https://wetransfer.com` — 23:52 (accessed but no confirmed upload)
- `https://www.linkedin.com/jobs/` — 22:01 (prior to incident window)

> **Finding:** OneDrive personal upload at 23:47 closely follows the USB copy completion at 23:31. This suggests a potential secondary exfiltration route via cloud storage.

---

### 5.3 USB Drive (E-003) — SanDisk 32GB

**Tool:** Autopsy v4.21.0, PhotoRec v7.2 (file carving)

- **File System:** NTFS
- **Capacity:** 32 GB / **Used:** 18.7 GB
- **Volume Label:** `AssetPro_Backup`

**Files found:**

| Folder | Contents | File Count | Size |
|---|---|---|---|
| `AssetPro_Backup\Source\` | `.cs`, `.py`, `.json` source code files | 612 | 11.2 GB |
| `AssetPro_Backup\Docs\` | `.docx`, `.pdf` project documentation | 165 | 4.1 GB |
| `AssetPro_Backup\Client\` | `.xlsx` client data files | 70 | 3.4 GB |
| `$RECYCLE.BIN\` | 3 deleted `.zip` files | 3 | (recovered via carving) |

**Deleted file recovery via data carving:**

```bash
# PhotoRec carving on DD image
photorec /d /cases/ERF-2026-031/E003_carved/ USB-SANDISK-32GB.dd
```

Three deleted `.zip` archives were recovered:
- `AssetPro_full_backup.zip` — 17.8 GB compressed archive of all project files
- `client_data_export.zip` — 3.3 GB
- `source_code_v4.zip` — 11.1 GB

> Zip archives appeared to be created with 7-Zip (consistent with Prefetch finding), then individual files were deleted after the archive was created — a common anti-forensic step.

---

### 5.4 Server Log Examination

#### Windows Security Event Log — Key Event IDs

| Event ID | Meaning | Finding |
|---|---|---|
| 4624 | Successful logon | `jthompson` logged on to `NOVA-WS-047` at 21:58:44 on 9 March |
| 4663 | Object access attempt | 847 file accesses on `\\FILESERVER01\Projects\AssetPro_v4\` from 22:04 to 23:31 |
| 4688 | Process creation | `robocopy.exe` launched at 22:12; `7z.exe` at 23:15 |
| 4648 | Logon with explicit credentials | Attempted logon to secondary account at 23:40 — failed |
| 4634 | Logoff | `jthompson` logged off `NOVA-WS-047` at 23:47 |

#### Firewall Log Findings

Palo Alto firewall log filtered for `jthompson`'s desktop IP (`10.0.14.47`) on 9 March:

| Time | Source | Destination | Port | Protocol | Bytes | Action |
|---|---|---|---|---|---|---|
| 23:47:02 | 10.0.14.47 | 13.107.42.12 (OneDrive) | 443 | HTTPS | 3,621,847,040 | Allowed |
| 23:52:11 | 10.0.14.47 | 104.20.224.55 (WeTransfer) | 443 | HTTPS | 1,024 | Allowed |

> **Finding:** 3.62 GB uploaded to Microsoft OneDrive at 23:47 — consistent with a compressed archive of the stolen files.

---

## 6. Phase 5 — Analysis

> **Purpose:** Correlate all examination findings to reconstruct events, establish a timeline, confirm or refute hypotheses, and identify the responsible party.

### 6.1 Timeline Reconstruction

Using all artefacts, the following timeline was reconstructed using **Autopsy's Timeline Analysis module** and cross-referenced with **log2timeline / Plaso**:

```
21:58:44  —  jthompson logs on to NOVA-WS-047 (Event ID 4624)
22:01:03  —  LinkedIn Jobs browsed (laptop browser history)
22:04:17  —  File server folder \\FILESERVER01\Projects\AssetPro_v4\ accessed (Event ID 4663)
22:09:33  —  SanDisk USB drive connected to NOVA-WS-047 (Registry – USBSTOR)
22:11:44  —  Navigation to E:\AssetPro_Backup\ on USB (ShellBags)
22:12:01  —  robocopy.exe launched (Prefetch, Event ID 4688)
             Command: robocopy \\FILESERVER01\Projects\AssetPro_v4 E:\AssetPro_Backup /E /LOG:robocopy_transfer.log
22:12–23:31 — 847 files (18.7 GB) copied from file server to USB drive (robocopy log, Event ID 4663 ×847)
23:15:44  —  7z.exe launched (Prefetch); ZIP archives created on USB (7-Zip)
23:28:00  —  ZIP archives created on USB: AssetPro_full_backup.zip, client_data_export.zip, source_code_v4.zip
23:31:47  —  USB drive safely removed (USBSTOR Registry – last write time)
23:31:48  —  Individual files deleted from USB, only ZIP archives remain (MFT timestamps, $LogFile)
23:45:09  —  robocopy_transfer.log deleted from desktop Recycle Bin (Recycle Bin metadata)
23:47:02  —  3.62 GB upload to OneDrive personal (13.107.42.12) via HTTPS (firewall log)
             Correlates with AssetPro_full_backup.zip file size (3.58 GB compressed)
23:47:22  —  jthompson logs off NOVA-WS-047 (Event ID 4634)
```

### 6.2 Hypothesis

> **Investigator's Conclusion (Working Hypothesis):**
>
> On 9 March 2026, between 21:58 and 23:47, user account `NOVATECH\jthompson`, operating from workstation `NOVA-WS-047`, deliberately and methodically:
>
> 1. Connected a personal USB drive to a company computer
> 2. Used `robocopy` to copy 847 proprietary source code and client data files to the USB drive
> 3. Compressed the files into ZIP archives using 7-Zip, then deleted the originals from the USB (retaining only archives — an anti-forensic technique to reduce file count visibility)
> 4. Deleted the robocopy log from the company computer's Recycle Bin
> 5. Uploaded a 3.62 GB archive to a personal OneDrive account, bypassing DLP controls that do not inspect encrypted HTTPS traffic to cloud providers
>
> The behaviour was intentional, systematic, and consistent with **insider data exfiltration** ahead of a planned resignation.

### 6.3 Attribution Confidence

| Evidence | Confidence Level |
|---|---|
| Domain logon under `jthompson` credentials | High — corroborated by Event ID 4624 + 4634 |
| Physical USB device connected to his workstation | High — USBSTOR serial matches physical USB (E-003) |
| Files on USB match file server contents | High — MD5 hash comparison on 100% of files |
| OneDrive upload originating from his workstation IP | High — firewall log, source IP `10.0.14.47` statically assigned to `NOVA-WS-047` |
| Upload size matches ZIP archive | High — 3.62 GB upload vs 3.58 GB zip (minor difference = HTTPS overhead) |
| Alternative user (i.e. credential theft) | Low probability — no evidence of prior credential compromise; MFA logs show `jthompson`'s registered phone was used |

### 6.4 Challenges Encountered and Solutions

| Challenge | Impact | Solution Applied |
|---|---|---|
| **OneDrive upload encrypted (HTTPS)** | Could not inspect file content in transit | Correlated upload size in firewall logs with recovered ZIP file size |
| **ZIP files deleted from USB** | Files appeared gone | Recovered via PhotoRec data carving from unallocated space |
| **Robocopy log deleted** | Key evidence intentionally destroyed | Recovered from Recycle Bin ($I and $R files intact) |
| **Large volume of event logs** | 1.2M event log entries | Filtered by Event ID + time window using `Get-WinEvent` PowerShell + grep |
| **RAM acquisition on sleeping laptop** | Volatile data at risk | Live RAM capture performed before shutdown using Magnet RAM Capture |

---

## 7. Phase 6 — Documentation

> **Purpose:** Produce a complete, accurate, and court-admissible forensic report that documents all steps, tools, findings, and conclusions.

### 7.1 Forensic Report Structure

The formal report (Report No. ERF-2026-031-FR) was produced by Dr. Amara Singh and peer-reviewed by Senior Forensic Analyst Kenji Watanabe (GREM, GCFE) of CyberTrace Forensics.

---

### FORENSIC INVESTIGATION REPORT — EXCERPT

**STRICTLY CONFIDENTIAL — LEGAL PROFESSIONAL PRIVILEGE**

| | |
|---|---|
| **Report Number** | ERF-2026-031-FR |
| **Case Name** | NovaTech Solutions Pty Ltd — Suspected Insider Data Exfiltration |
| **Examiner** | Dr. Amara Singh, CFCE, EnCE — Lead Digital Forensic Examiner |
| **Assisting Technician** | Priya Nair, BSc (Cybersecurity) — Digital Forensic Technician |
| **Peer Reviewer** | Kenji Watanabe, GREM, GCFE |
| **Date of Report** | 18 March 2026 |
| **Date of Incident** | 9–10 March 2026 |
| **Client** | NovaTech Solutions Pty Ltd, Level 4, 123 Eagle Street, Brisbane QLD 4000 |
| **Instructed By** | David Yu, General Counsel, NovaTech Solutions |
| **Investigation Period** | 10–17 March 2026 |

---

#### Executive Summary

An investigation into suspected data exfiltration by former employee James Thompson (NOVATECH\jthompson) was conducted between 10–17 March 2026. Forensic analysis of company workstation NOVA-WS-047, laptop NOVA-LT-019, a 32 GB USB drive, and associated server logs established that on 9 March 2026, the user account `jthompson` accessed 847 proprietary files on the company file server, copied them to a personally-owned USB drive using the `robocopy` utility, compressed the files using 7-Zip, and subsequently uploaded a 3.62 GB archive to a personal Microsoft OneDrive account. Evidence indicates deliberate attempts to conceal the activity, including deletion of the copy log. The evidence is assessed as sufficient to support civil proceedings and, subject to legal advice, potential referral to the Australian Federal Police for consideration under Section 477.1 of the Criminal Code Act 1995 (Cth).

---

#### Tools and Software

| Tool | Version | Purpose |
|---|---|---|
| FTK Imager | 4.7.1 | Forensic imaging and hash verification |
| Autopsy | 4.21.0 | File system analysis, artefact parsing |
| Magnet RAM Capture | 1.2 | Live RAM acquisition |
| Volatility3 | 2.5.0 | RAM analysis |
| Registry Explorer | 2.0.0.0 | Registry artefact analysis (USBSTOR, ShellBags) |
| X-Ways Forensics | 20.9 | File system deep analysis |
| PhotoRec | 7.2 | File carving from unallocated space |
| log2timeline / Plaso | 20240301 | Timeline creation and correlation |
| Eric Zimmermann Tools | Various | LNK, ShellBag, Jump List, Prefetch parsing |
| Wireshark | 4.2.3 | Packet capture verification (not used here but available) |
| PowerShell | 7.4 | Windows Event Log filtering |

#### Methodology

All examinations were conducted on forensic copies only. Original evidence was stored in a locked facility and has not been accessed since initial seizure. Hash values confirm the integrity of all copies. The methodology followed the **ACPO Good Practice Guide for Digital Evidence (v5)** and **NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response**.

> References:
> - [ACPO Good Practice Guide for Digital Evidence](https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf)
> - [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final)

---

### 7.2 Evidence Integrity Summary

All evidence hash values are recorded in the Chain of Custody Register (ERF-2026-031-CoC). Hash values confirmed match between source and forensic copies for all items. No evidence was modified during investigation. All actions were logged with timestamp, tool used, and operator name.

---

## 8. Phase 7 — Presentation

> **Purpose:** Communicate findings clearly to non-technical stakeholders (management, lawyers, court) in a credible, objective, and understandable manner.

### 8.1 Internal Briefing — NovaTech Management

**Date:** 19 March 2026, 10:00 AEST  
**Attendees:** Elena Marchetti (GM), David Yu (Legal), Michael Okonkwo (IT), NovaTech's external law firm (Minter Ellison Brisbane)

Dr. Singh presented a 20-minute briefing covering:

1. **What happened** — Plain-language summary of the exfiltration event
2. **How we know** — Key artefacts explained (USB registry, robocopy log, firewall upload)
3. **What was taken** — 847 files including source code (AssetPro v4) and client data
4. **What we could not determine** — Whether Thompson shared the data with a third party (OneDrive contents not accessible without a warrant or Thompson's cooperation)
5. **Recommendations** — Immediate steps: revoke all credentials, reset shared passwords Thompson knew, issue legal hold notice, consider AFP referral

> **Presentation principle:** Forensic experts must be able to explain technical findings to a non-technical audience. Avoid jargon; use analogies. For example: *"Think of the Shellbag entries like footprints in the carpet — even if you clean up the mess, the impressions remain."*

### 8.2 Preparation for Legal Proceedings

David Yu (Legal Counsel) was briefed on the evidentiary requirements for potential civil proceedings (breach of employment contract, breach of confidentiality) under Australian law:

- **Employment Contract Clause 14** — Confidentiality and Intellectual Property
- **Corporations Act 2001 (Cth), s183** — Misuse of information by employees
- **Australian Privacy Act 1988 (Cth)** — Client data (containing personal information) may trigger mandatory data breach notification under the **Notifiable Data Breaches Scheme (NDB)**

> **NDB Scheme reference:** [https://www.oaic.gov.au/privacy/notifiable-data-breaches](https://www.oaic.gov.au/privacy/notifiable-data-breaches)

### 8.3 Court-Ready Expert Witness Statement

Dr. Singh prepared a signed **Expert Witness Statement** in compliance with:
- **Uniform Civil Procedure Rules 2005 (NSW)** Schedule 7 (Expert witness code of conduct) — applicable by agreement as proceedings may be heard in NSW Federal Court
- **Evidence Act 1995 (Cth), s79** — Opinion evidence (expert opinion exception)

Key requirements satisfied:
- [x] Statement of qualifications and expertise
- [x] Statement that report prepared in accordance with expert's duty to the court (not to the client)
- [x] Clear separation of facts found vs. opinions formed
- [x] All tools and methods disclosed
- [x] Acknowledgement of limitations and alternative hypotheses considered

> **Reference:** [Evidence Act 1995 (Cth)](https://www.legislation.gov.au/Details/C2023C00210)

---

## 9. Phase 8 — Review

> **Purpose:** Evaluate the investigation process, identify what worked, what didn't, and what could be improved. Lessons learned.

### 9.1 Post-Investigation Review Meeting

**Date:** 25 March 2026, 14:00 AEST  
**Participants:** Dr. Amara Singh, Priya Nair, Kenji Watanabe (CyberTrace Forensics internal review)

### 9.2 What Went Well

| Area | Observation |
|---|---|
| **Live acquisition** | Identifying the sleeping laptop and capturing RAM before shutdown was critical — RAM evidence was pivotal |
| **Tool correlation** | Using multiple tools (Registry Explorer, Autopsy, Volatility) cross-corroborated findings and increased confidence |
| **Log preservation** | Exporting and hashing server logs on the day of the incident prevented potential log rotation loss |
| **Timeline analysis** | Plaso/log2timeline integration with Autopsy gave a comprehensive event timeline that was compelling to non-technical reviewers |

### 9.3 What Could Be Improved

| Area | Issue | Recommendation |
|---|---|---|
| **Cloud upload evidence** | Could not determine what was uploaded to OneDrive without a warrant | Recommend client enable Microsoft Defender for Cloud Apps (MCAS) for HTTPS inspection of cloud uploads at the proxy level |
| **DLP configuration** | DLP alert triggered after 500 files — earlier threshold would have alerted during the copy, not after | Recommend DLP rule: alert at 100 files + time-of-day restriction (no large transfers after 18:00) |
| **USB policy** | USB ports were unrestricted on desktop PCs | Recommend Group Policy to disable USB mass storage devices on all workstations; whitelist company-issued drives only |
| **Log retention** | Firewall logs older than 90 days were being overwritten | Recommend minimum 12-month log retention, centralised SIEM (e.g., Microsoft Sentinel or Splunk) |
| **RAM capture documentation** | RAM capture procedure not formally documented in SOP | Update Standard Operating Procedure to include live acquisition decision tree |

### 9.4 Legal Review

Minter Ellison confirmed the investigation met the requirements of the **Australian Standard AS ISO/IEC 27037:2015 — Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence**.

> **Reference:** [AS ISO/IEC 27037:2015](https://www.standards.org.au/standards-catalogue/sa-snz/informat/it-034/as-iso-slash-iec--27037-colon-2015)

---

## 10. Phase 9 — Closure

> **Purpose:** Formally conclude the investigation, archive all evidence and documentation, return or dispose of items, and issue the final case closure notice.

### 10.1 Outcomes

| Outcome | Detail |
|---|---|
| **Civil Proceedings** | NovaTech issued a Letter of Demand to James Thompson on 20 March 2026 through Minter Ellison, seeking injunctive relief to prevent further distribution of files, return of all copies, and damages |
| **AFP Referral** | On 22 March 2026, David Yu lodged a referral with the Australian Federal Police (AFP) Cybercrime Operations under s477.1 of the Criminal Code Act 1995 (Cth). AFP acknowledged receipt; investigation outcome pending. |
| **NDB Notification** | NovaTech notified the Office of the Australian Information Commissioner (OAIC) of the data breach on 14 March 2026 within the 30-day NDB scheme requirement, as client personal data (names, emails, ABNs) was included in the exfiltrated files |
| **Employee Terminated** | James Thompson's employment was terminated with cause on 11 March 2026, prior to his scheduled resignation date, based on internal HR and legal advice |

### 10.2 Evidence Disposition

| Evidence | Action |
|---|---|
| E-001 (Desktop PC) | Returned to NovaTech, re-imaged and redeployed |
| E-002 (Laptop) | Retained as potential exhibit; stored with NovaTech Legal |
| E-003 (USB Drive) | Retained as exhibit; held at CyberTrace Forensics secure evidence facility pending AFP investigation |
| E-004 to E-007 (Digital logs) | Encrypted copies retained at CyberTrace NAS for 7 years per evidence retention policy; originals on company servers |
| Forensic images | Retained at CyberTrace Forensics, encrypted, for 7 years |

### 10.3 Case Archiving

All case files were archived:

- **Case Folder:** `//FORENSIC-NAS/Archive/ERF-2026-031/`
- **Encrypted with:** VeraCrypt container, dual-key access (Dr. Singh + Kenji Watanabe)
- **Archive Index:** ERF-2026-031-INDEX.pdf
- **Retention Period:** 7 years (per Australian evidence and professional practice standards)

### 10.4 Case Closure Certificate

> **CASE CLOSURE NOTICE**
>
> Case Number: ERF-2026-031  
> Client: NovaTech Solutions Pty Ltd  
> Closed By: Dr. Amara Singh, Lead Forensic Examiner  
> Date of Closure: 25 March 2026  
>
> All investigative activities have been completed. All evidence items have been accounted for, hashed, and stored or returned in accordance with the chain of custody. The forensic report (ERF-2026-031-FR) has been issued. All case materials have been archived. This case is now formally closed pending any future legal proceedings that may require further expert input.

---

## Appendix A — Tools Reference

| Tool | Category | Platform | License | Link |
|---|---|---|---|---|
| **FTK Imager** | Imaging | Windows | Free | [https://www.exterro.com/ftk-imager](https://www.exterro.com/ftk-imager) |
| **Autopsy** | Analysis | Win/Linux/Mac | Open Source (Apache 2.0) | [https://www.autopsy.com](https://www.autopsy.com) |
| **Volatility3** | RAM Analysis | Win/Linux/Mac | Open Source (Volatility Licence) | [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| **Magnet RAM Capture** | RAM Acquisition | Windows | Free | [https://www.magnetforensics.com/resources/magnet-ram-capture/](https://www.magnetforensics.com/resources/magnet-ram-capture/) |
| **Magnet AXIOM** | Full Platform | Windows | Commercial | [https://www.magnetforensics.com/products/magnet-axiom/](https://www.magnetforensics.com/products/magnet-axiom/) |
| **X-Ways Forensics** | Analysis | Windows | Commercial | [https://www.x-ways.net/forensics/](https://www.x-ways.net/forensics/) |
| **EnCase** | Full Platform | Windows | Commercial | [https://www.opentext.com/products/encase-forensic](https://www.opentext.com/products/encase-forensic) |
| **Cellebrite UFED** | Mobile Forensics | Windows | Commercial | [https://cellebrite.com](https://cellebrite.com) |
| **PhotoRec / TestDisk** | File Carving | Win/Linux/Mac | Open Source (GPL) | [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) |
| **log2timeline / Plaso** | Timeline | Linux | Open Source | [https://github.com/log2timeline/plaso](https://github.com/log2timeline/plaso) |
| **Eric Zimmermann Tools** | Artefact Analysis | Windows | Free | [https://ericzimmerman.github.io](https://ericzimmerman.github.io) |
| **Wireshark** | Network Analysis | Win/Linux/Mac | Open Source (GPLv2) | [https://www.wireshark.org](https://www.wireshark.org) |
| **DumpIt** | RAM Capture | Windows | Free | [https://www.comae.com](https://www.comae.com) |
| **Oxygen Forensic Detective** | Mobile Forensics | Windows | Commercial | [https://www.oxygen-forensic.com](https://www.oxygen-forensic.com) |

---

## Appendix B — Laws and Regulations

| Instrument | Jurisdiction | Relevance |
|---|---|---|
| [Criminal Code Act 1995 (Cth) — s477.1](https://www.legislation.gov.au/Details/C2021C00183) | Australia (Federal) | Unauthorised access to restricted data |
| [Criminal Code Act 1995 (Cth) — s478.1](https://www.legislation.gov.au/Details/C2021C00183) | Australia (Federal) | Unauthorised impairment of data |
| [Privacy Act 1988 (Cth)](https://www.legislation.gov.au/Details/C2022C00199) | Australia (Federal) | Protection of personal information; NDB Scheme |
| [Evidence Act 1995 (Cth)](https://www.legislation.gov.au/Details/C2023C00210) | Australia (Federal) | Admissibility of digital evidence; expert opinion |
| [Corporations Act 2001 (Cth) s183](https://www.legislation.gov.au/Details/C2023C00093) | Australia (Federal) | Misuse of company information |
| [AS ISO/IEC 27037:2015](https://www.standards.org.au/standards-catalogue/sa-snz/informat/it-034/as-iso-slash-iec--27037-colon-2015) | Australia / International | Digital evidence handling standard |
| [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final) | USA (best practice adopted internationally) | Forensic techniques in incident response |
| [NIST SP 800-101 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final) | USA (best practice) | Mobile device forensics |
| [ACPO Good Practice Guide v5](https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf) | UK (widely adopted in AUS) | Digital evidence good practice principles |

---

## Appendix C — Chain of Custody Template

```
╔══════════════════════════════════════════════════════════╗
║           CHAIN OF CUSTODY — EVIDENCE ITEM               ║
╠══════════════════════════════════════════════════════════╣
║ Case Number:  ______________________                      ║
║ Evidence ID:  ______________________                      ║
║ Description:  ______________________                      ║
║ Make/Model:   ______________________                      ║
║ Serial No.:   ______________________                      ║
║ Condition:    ______________________                      ║
║ Hash (MD5):   ______________________                      ║
║ Hash (SHA-256): ____________________                      ║
╠══════════════════════════════════════════════════════════╣
║  #  │ Date/Time │ Received From │ Received By │ Purpose  ║
║─────┼───────────┼───────────────┼─────────────┼──────────║
║  1  │           │               │             │          ║
║  2  │           │               │             │          ║
║  3  │           │               │             │          ║
╠══════════════════════════════════════════════════════════╣
║ Storage Location: _______________________                 ║
║ Seal Number:      _______________________                 ║
╚══════════════════════════════════════════════════════════╝
```

---

## References

- ACPO 2012, *Good Practice Guide for Digital Evidence*, Version 5, Association of Chief Police Officers, viewed 30 March 2026, <https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf>

- CGSecurity 2025, *TestDisk Download*, CGSecurity, viewed 2 October 2025, <https://www.cgsecurity.org/wiki/TestDisk_Download>

- Darrington, J 2023, *The phases of the digital forensics investigation process*, Graylog, viewed 27 July 2023, <https://graylog.org/post/the-phases-of-the-digital-forensics-investigation-process/>

- EC-Council n.d., *What is digital forensics?*, EC-Council, viewed 27 July 2023, <https://www.eccouncil.org/cybersecurity/what-is-digital-forensics/>

- ERMProtect n.d., *What are the 5 stages of a digital forensics investigation?*, ERMProtect, viewed 27 July 2023, <https://ermprotect.com/blog/what-are-the-5-stages-of-a-digital-forensics-investigation/>

- Mikus, N 2005, *Basic Data Carving Test #1*, Source Forge, viewed 2 October 2025, <https://dftt.sourceforge.net/test11/index.html>

- NIST 2006, *SP 800-86: Guide to Integrating Forensic Techniques into Incident Response*, National Institute of Standards and Technology, <https://csrc.nist.gov/publications/detail/sp/800-86/final>

- NIST 2014, *SP 800-101 Rev. 1: Guidelines on Mobile Device Forensics*, National Institute of Standards and Technology, <https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final>

- OAIC n.d., *Notifiable Data Breaches Scheme*, Office of the Australian Information Commissioner, <https://www.oaic.gov.au/privacy/notifiable-data-breaches>

- Standards Australia 2015, *AS ISO/IEC 27037:2015 — Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*, Standards Australia, <https://www.standards.org.au/standards-catalogue/sa-snz/informat/it-034/as-iso-slash-iec--27037-colon-2015>

- Digital Corpora 2018, *2018 Lone Wolf Scenario*, Digital Corpora, <https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/>

---

*Document prepared for educational purposes. All company names, people, and events are fictional. Any resemblance to real persons or organisations is coincidental.*

*© CyberTrace Forensics (Hypothetical) — ERF-2026-031 | Classification: EDUCATIONAL / PUBLIC RESOURCE*
