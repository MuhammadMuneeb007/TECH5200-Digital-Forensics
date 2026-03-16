# Digital Forensics — Complete Reference Pack

> Includes the Case Worksheet Pack, NIST Case Study breakdown, complete tool reference (70+ tools), and types of digital forensics.

---

## Table of Contents

1. [Case Worksheet Pack](#1-case-worksheet-pack)
2. [NIST Real Case Study](#2-nist-real-case-study)
3. [Forensic Stage Breakdown Table](#3-forensic-stage-breakdown-table)
4. [Types of Digital Forensics](#4-types-of-digital-forensics)
5. [Complete Tool Reference](#5-complete-tool-reference)
   - [Imaging & Acquisition](#imaging--acquisition)
   - [All-in-One Platforms](#all-in-one-platforms)
   - [File System Analysis](#file-system-analysis)
   - [File Recovery & Carving](#file-recovery--carving)
   - [Windows Registry](#windows-registry)
   - [Windows Artifacts](#windows-artifacts)
   - [Browser Forensics](#browser-forensics)
   - [Email Forensics](#email-forensics)
   - [Memory Forensics](#memory-forensics)
   - [Network Forensics](#network-forensics)
   - [CD / DVD / Optical Forensics](#cd--dvd--optical-forensics)
   - [Timeline Analysis](#timeline-analysis)
   - [Hash & Verification](#hash--verification)
   - [Metadata Analysis](#metadata-analysis)
   - [Triage & Collection](#triage--collection)
   - [Enterprise Platforms](#enterprise-platforms)
   - [Linux Forensic Distros](#linux-forensic-distros)
   - [Anti-Forensic Tools (Investigator Awareness)](#anti-forensic-tools-investigator-awareness)
6. [Quick Reference — Best Free Stack for Windows PC](#6-quick-reference--best-free-stack-for-windows-pc)

---

## 1. Case Worksheet Pack

Use this worksheet at each stage of a digital forensics investigation to ensure nothing is missed.

---

### Stage 1 — Identification

- What happened?
- What systems/devices are involved?
- What evidence may exist?
- Where is it stored?
- What is volatile?
- What needs urgent preservation?

---

### Stage 2 — Preservation

- Was the device isolated?
- Was it photographed?
- Was a forensic image created?
- Was a hash recorded?
- Was chain of custody started?
- Who handled the evidence?

---

### Stage 3 — Analysis

- What artefacts were found?
- What is the timeline?
- What supports the fraud theory?
- What contradicts it?
- Are there alternate explanations?
- What remains unknown?

---

### Stage 4 — Documentation

- Were all actions logged?
- Were tool names and versions recorded?
- Were screenshots taken?
- Are timestamps included?
- Can another examiner repeat the work?

---

### Stage 5 — Presentation

- What happened in plain English?
- What evidence supports this?
- How confident are we?
- What legal or ethical limits apply?
- What should happen next?

---

## 2. NIST Real Case Study

**Sources:**
- [NIST CFReDS Data Leakage Case — Full Answers PDF](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [FBI Forensic Spotlight — Digital Forensic Examination: A Case Study](https://leb.fbi.gov/spotlights/forensic-spotlight-digital-forensic-examination-a-case-study)

---

### Case Summary

The suspect planned the theft by searching the web for data-leakage methods, anti-forensics, Windows artifacts, and ways to bypass detection. He connected an authorised USB, searched for confidential files, copied them to his PC, renamed them to look harmless, emailed a sample file, and used cloud-related activity. The next day he copied more files to a second USB, quick-formatted that USB to hide the transfer, burned data onto a CD, and deleted visible traces. On the final day he searched for anti-forensic tools, downloaded and installed Eraser and CCleaner, wiped files, removed software, and disconnected Google Drive.

Investigators can still reconstruct the leakage through file-system metadata, browser history, email artifacts, cloud logs, removable-media traces, Windows Search data, thumbnails, recovered deleted entries, and timeline analysis.

---

### Tools the Criminal Used

| Forensic Stage | Tools Used by the Suspect |
|----------------|--------------------------|
| Identification | Microsoft Internet Explorer, Google Chrome, Google Search, Bing, Microsoft Outlook |
| Preservation | None explicitly named |
| Analysis | Windows Search, Windows Explorer, RM#1 SanDisk Cruzer Fit USB |
| Documentation | None explicitly named |
| Presentation / Exfiltration | Microsoft Outlook, Google Drive, Apple iCloud, RM#2 SanDisk Cruzer Fit USB, RM#3 CD-R, CCleaner, Eraser |

---

### Tools the Authorities Used

| Forensic Stage | Tools Used by Investigators |
|----------------|-----------------------------|
| Identification | Portable write blockers |
| Preservation | FTK Imager 3.4.0.1, EnCase Imager 7.10.00.103, FTK Imager 3.3.0.5, EnCase Imager 7.09.00.111, Tableau USB Bridge T8-R2, bchunk v1.2.0 |
| Analysis | PhotoRec |
| Documentation | FTK Imager, EnCase Imager |
| Presentation | Not explicitly named in the PDF |

---

## 3. Forensic Stage Breakdown Table

| Stage | Scenario / What Happened | What the Suspect Used | What Investigators Examined | What They Did | Tool / Method Used |
|-------|--------------------------|-----------------------|----------------------------|---------------|--------------------|
| Identification | Employee planned to leak confidential data to a rival and was caught carrying a USB and CD out of the company | Email, authorized USB (RM#1), second USB (RM#2), CD-R (RM#3), Windows PC | PC, USB devices, CD, Outlook email, browser history, cloud traces, file-system metadata, deleted data | Defined scope, listed target systems/devices, identified likely leakage paths and possible policy violations | Evidence scoping, device triage, artifact identification, write-blocked inspection at checkpoint |
| Identification | Suspect researched how to leak data and how to avoid detection | Google Chrome, Internet Explorer, Google/Bing | Search terms about data leakage, digital forensics, anti-forensics, event logs, cloud storage, file deletion | Used browser artifacts to show intent and premeditation | Web-browser forensics: history, cache, cookies, search history |
| Identification | Suspect used an authorized USB to access confidential files | RM#1 authorized USB | USB connection records, file-open traces, copied-file traces | Linked confidential files on RM#1 to the suspect's PC activity | Windows forensics, external-device analysis, opened-files/directories, file-system metadata |
| Preservation | Devices were detected at the checkpoint and sent to the lab | USB and CD seized physically | Original PC image, USB images, CD image, hashes | Preserved media integrity and verified images with hashes | Portable write blockers, forensic imaging, MD5/SHA-1 verification, FTK Imager, EnCase Imager, bchunk |
| Preservation | Investigators needed stable copies before deep analysis | Disk images of PC, RM#2, RM#3 | Acquisition details, image formats, verification hashes | Worked from forensic images instead of altering originals | Forensic imaging workflow; DD/E01 formats; hash verification |
| Analysis | Suspect searched for confidential content and opened sensitive files | Windows Search, Explorer, Office files | Search keyword "secret," opened proposal and design files, recent items, shell artifacts | Reconstructed that the suspect intentionally located and viewed confidential material | Windows Search artifacts, recent files, Jump Lists, ShellBags, Office MRU, file metadata |
| Analysis | Suspect copied files from RM#1 to the PC and renamed them to harmless-looking names/extensions | RM#1, Desktop folder, Windows Explorer | Original paths, copied-file traces, rename events, misleading names like `landscape.png` and `space_and_earth.mp4` | Showed that renaming was concealment, not normal work | NTFS metadata, timestamps, transaction logs, opened-file traces, file signature/format analysis |
| Analysis | Suspect emailed a sample file to the conspirator | Microsoft Outlook | Email messages, attachment evidence, sender/recipient timeline | Proved communication and sample-data transfer | Email forensics: Outlook examination, email/attachment analysis |
| Analysis | Suspect used cloud-service traces | Google Drive, possibly iCloud installer | Installation traces, deleted sync databases, sync logs, registry keys | Established cloud-related activity and deleted-file actions | Cloud artifact analysis using `sync_log.log`, deleted SQLite DBs, registry review |
| Analysis | Suspect copied more files to RM#2, then quick-formatted it | RM#2 USB | Deleted directory entries, recoverable filenames, traces of quick format | Recovered evidence of copied files despite formatting | FAT metadata recovery, deleted-data recovery, optional carving; PhotoRec |
| Analysis | Suspect burned files to CD-R and tried to hide them with extra sessions and deletions | CD-R (RM#3) | Burn-session artifacts, hidden/deleted files, recoverable original filenames | Showed CD burning and concealment tactics | CD/DVD burning analysis, UDF file-system analysis, data carving, file-signature analysis |
| Analysis | Suspect used anti-forensic tools on the final day | Eraser, CCleaner, Google Drive sign-out | Searches for anti-forensics, downloads, installs, run history, wipe actions, uninstall actions, cloud disconnect log | Reconstructed deliberate evidence-destruction attempts | Program execution history, browser history, uninstall traces, log review, deleted-data recovery |
| Documentation | Investigators needed a full record of findings | Case notes, hash records, recovered filenames, timestamps | Device details, acquisition details, artifact paths, timestamps, recovered files | Recorded every artifact, hash, file path, and timeline event so the case could be reproduced | Formal forensic documentation, chain-of-custody style recording, timeline reporting |
| Presentation | Final explanation of the case | Timeline, recovered files, email/cloud/browser traces, anti-forensic traces | Full leakage sequence from planning to concealment | Explained how the suspect prepared, copied, disguised, transferred, and tried to erase evidence | User-behaviour analysis and forensic timeline visualisation |

---

## 4. Types of Digital Forensics

| Type | What It Is | Tools Used |
|------|-----------|-----------|
| **Computer Forensics** | Investigation of computers and laptops to recover files, deleted data, browser history, emails, and system logs. | Autopsy (Free), EnCase Forensic (Paid), FTK Imager (Free) |
| **Network Forensics** | Analysis of network traffic, packets, and communication logs to detect hacking or unauthorised access. | Wireshark (Free), NetworkMiner (Free/Paid), Snort (Free) |
| **Mobile Forensics** | Investigation of smartphones and tablets to recover messages, call logs, photos, app data, and location information. | Cellebrite UFED (Paid), Oxygen Forensic Detective (Paid), ADB (Free) |
| **IoT Forensics** | Investigation of smart devices such as smart cameras, smart speakers, smart watches, and home automation devices. | IoT Inspector (Free), Firmware Analysis Toolkit (Free), Binwalk (Free) |
| **Storage Forensics** | Analysis of storage devices like hard drives, SSDs, USB drives, and memory cards to recover data. | FTK Imager (Free), Guymager (Free), X-Ways Forensics (Paid) |
| **Cloud Forensics** | Investigation of data stored in cloud systems such as Google Drive, AWS, or Dropbox. | Magnet AXIOM (Paid), AWS CloudTrail (Free/Paid), Elasticsearch (Free) |
| **Email Forensics** | Analysis of email messages, headers, and attachments to investigate fraud, phishing, or cybercrime. | MailXaminer (Paid), Aid4Mail (Paid), Autopsy (Free) |
| **Memory (RAM) Forensics** | Analysis of volatile memory to detect malware, running processes, and hidden activities. | Volatility (Free), Rekall (Free), Belkasoft RAM Capturer (Free) |

---

## 5. Complete Tool Reference

> 70+ tools across all forensic investigation stages. Includes free, freemium, and paid options for Windows, Linux, and macOS.
>
> Additional NirSoft tools: [https://www.nirsoft.net](https://www.nirsoft.net)

---

### Imaging & Acquisition

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **FTK Imager** | Free | Windows | Forensic disk imaging, preview evidence, acquire drives, USBs, CDs. Creates E01/DD images with MD5/SHA-1 hash verification. Directly mentioned in NIST data leakage case. | [Download](https://www.exterro.com/digital-forensics-software/ftk-imager) |
| **EnCase Forensic** | Paid | Windows | Enterprise-grade forensic imaging, acquisition, and case management. Used in the NIST data leakage case for imaging. | [Download](https://www.opentext.com/products/encase-forensic) |
| **Guymager** | Free | Linux | Fast open-source forensic imager. Supports EWF/DD/AFF formats with MD5/SHA hash verification. | [Download](https://guymager.sourceforge.io) |
| **dd / dcfldd** | Free | Linux / macOS | Command-line disk imaging built into Linux/macOS. `dcfldd` is the enhanced forensic version with on-the-fly hashing. | [Download](https://github.com/adulau/dcfldd) |
| **bchunk** | Free | Linux / Windows | Converts CD RAW/CUE images to ISO/CDR format. Directly mentioned in the NIST case for CD-R (RM#3) analysis. | [Download](https://github.com/hessu/bchunk) |

---

### All-in-One Platforms

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Autopsy** | Free | Windows / Linux / macOS | Full open-source digital forensics platform. Timeline analysis, file carving, keyword search, email analysis, browser history, registry. Free GUI front-end for The Sleuth Kit. | [Download](https://www.autopsy.com/download) |
| **Forensic Toolkit (FTK)** | Paid | Windows | Industry-standard complete forensic investigation suite. Email analysis, registry, internet history, password recovery, indexing. | [Download](https://www.exterro.com/digital-forensics-software/forensic-toolkit) |
| **X-Ways Forensics** | Paid | Windows | Lightweight but powerful professional forensics tool. Fast disk imaging, file carving, NTFS analysis, email parsing. Lower cost than FTK/EnCase. | [Download](https://www.x-ways.net/forensics) |
| **AXIOM (Magnet Forensics)** | Paid | Windows | Recovers and analyses artifacts from computers, mobile, cloud, and vehicles. Strong cloud and app artifact support. | [Download](https://www.magnetforensics.com/products/magnet-axiom) |
| **Belkasoft Evidence Center** | Paid | Windows | All-in-one: disk, memory, mobile, cloud. Strong for SQLite databases, browsers, and messengers. | [Download](https://belkasoft.com/ec) |
| **OSForensics** | Freemium | Windows | Fast file indexing, password recovery, memory analysis, timeline, and hash matching. Free trial available. | [Download](https://www.osforensics.com/download.html) |

---

### File System Analysis

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **The Sleuth Kit (TSK)** | Free | Windows / Linux / macOS | Command-line library for analysing disk images. Analyses NTFS, FAT, EXT, HFS+. Powers Autopsy. | [Download](https://www.sleuthkit.org/sleuthkit) |
| **MFTECmd** | Free | Windows | Parses the NTFS Master File Table ($MFT). Shows timestamps, file paths, and file creation/modification history. Key for timeline reconstruction. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **NTFS Log Tracker** | Free | Windows | Parses NTFS `$LogFile` and `$UsnJrnl` to reconstruct file operations: create, rename, delete, overwrite. | [Download](https://sites.google.com/site/forensicnote/ntfs-log-tracker) |

---

### File Recovery & Carving

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **PhotoRec** | Free | Windows / Linux / macOS | File carving tool that recovers deleted files based on file signatures. Directly mentioned in NIST case for RM#2 USB recovery. Ignores filesystem structure. | [Download](https://www.cgsecurity.org/wiki/PhotoRec) |
| **TestDisk** | Free | Windows / Linux / macOS | Recovers lost partitions and makes non-booting disks bootable again. Companion tool to PhotoRec. | [Download](https://www.cgsecurity.org/wiki/TestDisk) |
| **Recuva** | Free | Windows | User-friendly file recovery for deleted files on FAT/NTFS. Good for quick USB and drive triage. | [Download](https://www.ccleaner.com/recuva) |
| **Foremost** | Free | Linux | Command-line file carver based on file headers, footers, and data structures. Runs directly on raw image files. | [Download](https://github.com/jonstewart/foremost) |
| **Scalpel** | Free | Linux / Windows | Fast file carver based on Foremost with highly configurable file header/footer definitions. | [Download](https://github.com/sleuthkit/scalpel) |

---

### Windows Registry

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Registry Explorer** | Free | Windows | GUI tool for parsing and analysing Windows registry hives. Shows USB history, program execution, user activity, and cloud-related registry keys. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **RegRipper** | Free | Windows / Linux | Automated registry parsing with plugins. Extracts USB history, RecentDocs, MRU lists, ShellBags, timezone, and user profiles. | [Download](https://github.com/keydet89/RegRipper3.0) |
| **FTK Registry Viewer** | Free | Windows | Standalone registry viewer from Exterro. Reads hive files offline and shows keys, values, and timestamps. | [Download](https://www.exterro.com/digital-forensics-software/ftk-imager) |

---

### Windows Artifacts

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **ShellBags Explorer** | Free | Windows | Analyses ShellBag registry keys to show folders the user browsed — even on removed drives. Key for proving file access. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **JumpList Explorer** | Free | Windows | Parses Windows Jump Lists (`.automaticDestinations`). Shows recently opened files per application. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **PECmd** | Free | Windows | Parses Windows Prefetch files to show which programs were executed, how many times, and when. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **LECmd** | Free | Windows | Parses Windows LNK (shortcut) files. Shows the target file path, MAC times, and volume serial — proving files were accessed. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **WxTCmd** | Free | Windows | Parses Windows 10 Timeline (`ActivitiesCache.db`) to reconstruct user activity and application usage history. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **USBDeview (NirSoft)** | Free | Windows | Lists all USB devices ever connected to the system with timestamps, serial numbers, and device details. | [Download](https://www.nirsoft.net/utils/usb_devices_view.html) |
| **LastActivityView (NirSoft)** | Free | Windows | Shows recent system activity: executed programs, opened files, network connections, logon/logoff events. | [Download](https://www.nirsoft.net/utils/computer_activity_view.html) |
| **Event Log Explorer** | Freemium | Windows | GUI viewer for Windows Event Logs (.evtx). Filters by event ID, user, and date. Crucial for logon/logoff, USB plug-in, and process execution events. | [Download](https://eventlogxp.com) |
| **FullEventLogView (NirSoft)** | Free | Windows | Views all Windows event log entries in one unified list. Free and portable — no installation needed. | [Download](https://www.nirsoft.net/utils/full_event_log_view.html) |

---

### Browser Forensics

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **BrowsingHistoryView (NirSoft)** | Free | Windows | Extracts and shows browser history from Chrome, Firefox, IE, and Edge across multiple profiles in a single view. | [Download](https://www.nirsoft.net/utils/browsing_history_view.html) |
| **Hindsight** | Free | Windows / Linux / macOS | Open-source Chrome/Chromium forensics tool. Parses history, downloads, cookies, cache, preferences, and extensions. | [Download](https://github.com/obsidianforensics/hindsight) |
| **DB Browser for SQLite** | Free | Windows / Linux / macOS | GUI tool for opening and querying SQLite databases. Used to inspect Chrome history, Firefox places, and cloud sync DBs as referenced in the NIST case. | [Download](https://sqlitebrowser.org/dl) |
| **ChromeCacheView (NirSoft)** | Free | Windows | Views and extracts files stored in the Google Chrome browser cache. | [Download](https://www.nirsoft.net/utils/chrome_cache_view.html) |
| **MZCacheView (NirSoft)** | Free | Windows | Firefox cache viewer. Shows cached files, URLs, content type, and last accessed time. | [Download](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) |

---

### Email Forensics

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Kernel OST/PST Viewer** | Free | Windows | Opens and views Outlook `.pst` and `.ost` files without needing Outlook installed. Free viewer for email forensics. | [Download](https://www.nucleustechnologies.com/pst-viewer.html) |
| **Mail PassView (NirSoft)** | Free | Windows | Recovers email account passwords stored by Outlook, Thunderbird, and Windows Live Mail. | [Download](https://www.nirsoft.net/utils/mailpv.html) |
| **MailXaminer** | Paid | Windows | Professional email forensics tool supporting 80+ email formats. Analyses headers, attachments, metadata, and conversations. | [Download](https://www.mailxaminer.com) |
| **Aid4Mail** | Paid | Windows / macOS | Email forensic conversion and investigation. Supports PST, MBOX, EML, NSF. Used for email acquisition and analysis. | [Download](https://www.fookes.com/aid4mail) |

---

### Memory Forensics

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Volatility** | Free | Windows / Linux / macOS | The gold standard for RAM/memory forensics. Extracts processes, network connections, registry hives, passwords, and malware artefacts from memory dumps. | [Download](https://www.volatilityfoundation.org/releases) |
| **Rekall** | Free | Windows / Linux / macOS | Advanced memory analysis framework forked from Volatility. Supports live memory analysis. | [Download](https://github.com/google/rekall) |
| **DumpIt** | Free | Windows | Single-executable Windows memory acquisition tool. Captures a full RAM dump with one click. | [Download](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows) |
| **Magnet RAM Capture** | Free | Windows | Free Windows memory acquisition tool from Magnet Forensics. Captures full physical memory for later analysis in Volatility. | [Download](https://www.magnetforensics.com/resources/magnet-ram-capture) |

---

### Network Forensics

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Wireshark** | Free | Windows / Linux / macOS | Industry-standard packet capture and analysis. Inspects network traffic, protocols, and data transfers for evidence of exfiltration. | [Download](https://www.wireshark.org/download.html) |
| **NetworkMiner** | Freemium | Windows / Linux | Network forensic analysis tool (NFAT). Reconstructs files, sessions, and credentials from PCAP files. | [Download](https://www.netresec.com/?page=NetworkMiner) |
| **Xplico** | Free | Linux | Reconstructs application data (emails, HTTP, VoIP) from PCAP network captures. | [Download](https://www.xplico.org) |

---

### CD / DVD / Optical Forensics

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **IsoBuster** | Freemium | Windows | Recovers data from CDs, DVDs, Blu-rays including multisession discs, deleted UDF files, and hidden sessions. Directly relevant to the CD-R (RM#3) in the NIST case. | [Download](https://www.isobuster.com/download.php) |
| **CDCheck** | Free | Windows | Verifies and recovers data from damaged or multisession CDs and DVDs. | [Download](http://www.mitec.cz/cdcheck.html) |

---

### Timeline Analysis

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **log2timeline / Plaso** | Free | Linux / macOS / Windows | Automatic super-timeline creation from disk images and log files. Extracts timestamps from 100+ artefact types into one searchable timeline. | [Download](https://github.com/log2timeline/plaso) |
| **Timeline Explorer** | Free | Windows | GUI viewer for CSV/xlsx timelines — pairs perfectly with log2timeline output. Filter, sort, and colour-code timeline events. | [Download](https://ericzimmerman.github.io/#!index.md) |
| **Timesketch** | Free | Linux (server) | Web-based collaborative timeline investigation tool. Upload Plaso timelines and investigate as a team. | [Download](https://timesketch.org) |

---

### Hash & Verification

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **HashMyFiles (NirSoft)** | Free | Windows | Calculates MD5, SHA-1, SHA-256, SHA-512 hashes for files. Used to verify forensic image integrity. | [Download](https://www.nirsoft.net/utils/hash_my_files.html) |
| **HashCalc** | Free | Windows | Fast hash calculator supporting MD5, SHA-1, SHA-256, CRC32, and more for evidence integrity verification. | [Download](https://www.slavasoft.com/hashcalc) |
| **md5deep / hashdeep** | Free | Windows / Linux / macOS | Command-line recursive hashing tool. Computes and audits hash sets across entire directory trees or disk images. | [Download](https://github.com/jessek/hashdeep) |

---

### Metadata Analysis

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **ExifTool** | Free | Windows / Linux / macOS | Extracts metadata from images, documents, PDFs, and videos — timestamps, GPS, author, software used. Useful for proving file origin and modification history. | [Download](https://exiftool.org) |

---

### Triage & Collection

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **KAPE (Kroll Artifact Parser & Extractor)** | Free | Windows | Lightning-fast triage tool. Collects targeted forensic artefacts (browsers, registry, event logs, prefetch) from live systems without imaging the whole drive. | [Download](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) |
| **CyLR** | Free | Windows / Linux / macOS | Live response collection tool — collects forensic artefacts quickly from Windows, Linux, and macOS for rapid triage. | [Download](https://github.com/orlikoski/CyLR) |
| **IRTriage** | Free | Windows | Windows incident response triage tool that automates collection of volatile data, event logs, registry, and prefetch files. | [Download](https://github.com/AJMartel/IRTriage) |
| **Bulk Extractor** | Free | Windows / Linux / macOS | Scans disk images and extracts emails, URLs, credit cards, phone numbers, and other artefacts without parsing the filesystem. Fast and filesystem-agnostic. | [Download](https://github.com/simsong/bulk_extractor) |

---

### Enterprise Platforms

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **NUIX Workstation** | Paid | Windows | High-performance processing of large evidence sets. Handles email, cloud, mobile, and endpoint data. Used by law enforcement globally. | [Download](https://www.nuix.com/products/nuix-workstation) |
| **Cellebrite UFED** | Paid | Windows | Industry-leading mobile device forensics — bypasses locks, extracts full physical dumps of phones. Also includes PC triage capabilities. | [Download](https://cellebrite.com/en/ufed) |
| **Oxygen Forensic Detective** | Paid | Windows | Extracts and analyses data from mobile, cloud, drones, and IoT. Strong cloud account acquisition capabilities. | [Download](https://www.oxygen-forensic.com/en/products/oxygen-forensic-detective) |

---

### Linux Forensic Distros

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Paladin (Sumuri)** | Free | Bootable USB / DVD | Bootable Ubuntu-based forensic distro with 100+ pre-installed tools. Write-blocking, imaging, and analysis in one live environment. | [Download](https://sumuri.com/software/paladin) |
| **CAINE** | Free | Bootable USB / DVD | Linux forensic live distro with automated write-blocking on mount and a full forensic toolset pre-installed. | [Download](https://www.caine-live.net) |
| **Tsurugi Linux** | Free | Bootable USB / DVD | DFIR-focused Linux distro with OSINT and malware analysis tools pre-installed alongside standard forensic tools. | [Download](https://tsurugi-linux.org) |
| **SANS SIFT Workstation** | Free | Linux VM / Install | Ubuntu-based forensic workstation built by SANS. Includes Sleuth Kit, Volatility, log2timeline, and dozens of DFIR tools. | [Download](https://www.sans.org/tools/sift-workstation) |

---

### Anti-Forensic Tools (Investigator Awareness)

> These tools are listed so investigators understand what suspects may use to destroy evidence. Their install traces, execution history, and uninstall artefacts are themselves forensic evidence.

| Tool | Cost | Platform | Purpose | Download |
|------|------|----------|---------|----------|
| **Eraser** | Free | Windows | Secure file deletion tool. Directly used by the suspect in the NIST data leakage case. Investigators look for its execution history, search queries, and uninstall logs. | [Download](https://eraser.heidi.ie) |
| **CCleaner** | Freemium | Windows / macOS | System cleaner used as an anti-forensic measure. Run history and installation artefacts are themselves evidence. Directly used in the NIST case. | [Download](https://www.ccleaner.com/ccleaner/download) |

---

## 6. Quick Reference — Best Free Stack for Windows PC

| Goal | Recommended Free Tool(s) |
|------|--------------------------|
| Disk imaging | FTK Imager |
| Full investigation platform | Autopsy |
| Windows artefact parsing | Eric Zimmerman's Tools (ShellBags Explorer, JumpList Explorer, PECmd, LECmd, MFTECmd, Registry Explorer, Timeline Explorer) |
| Browser history | BrowsingHistoryView, Hindsight, DB Browser for SQLite |
| File recovery | PhotoRec + Recuva |
| Memory acquisition | Magnet RAM Capture |
| Memory analysis | Volatility |
| Network capture | Wireshark |
| Fast triage | KAPE |
| Timeline | log2timeline / Plaso + Timeline Explorer |
| Hash verification | HashMyFiles or hashdeep |
| Metadata | ExifTool |
| USB history | USBDeview |
| CD/DVD analysis | IsoBuster (free tier) |
| Clean bootable environment | CAINE or SANS SIFT Workstation |

---

*Tools directly referenced in the NIST CFReDS Data Leakage Case: FTK Imager, EnCase, bchunk, PhotoRec, Eraser, CCleaner, IsoBuster, DB Browser for SQLite.*
