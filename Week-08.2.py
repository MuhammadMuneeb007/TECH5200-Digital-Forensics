import json
import csv
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(r"C:\Users\munee\Desktop\PhD\Teaching\TECH5200")

# This should match the output folder created by your first script
INPUT_DIR = BASE_DIR / "VolatilityPythonOverview"

OUTPUT_DIR = BASE_DIR / "VolatilityPythonOverview"
OUTPUT_DIR.mkdir(exist_ok=True)


FILES = {
    "info": INPUT_DIR / "01_windows_info.json",
    "pslist": INPUT_DIR / "02_pslist.json",
    "pstree": INPUT_DIR / "03_pstree.json",
    "psscan": INPUT_DIR / "03b_psscan.json",
    "cmdline": INPUT_DIR / "04_cmdline.json",
    "netscan": INPUT_DIR / "05_netscan.json",
    "dlllist": INPUT_DIR / "06_dlllist.json",
    "malfind": INPUT_DIR / "07_malfind.json",
    "hivelist": INPUT_DIR / "08_hivelist.json",
}


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path):
    if not path.exists():
        print(f"[MISSING] {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not read {path}: {e}")
        return None


def extract_rows_from_volatility_json(data):
    """
    Extracts rows from Volatility 3 JSON renderer output.
    It handles nested tree/grid output.
    """
    if not data:
        return []

    if isinstance(data, dict):
        rows = data.get("rows")
        if isinstance(rows, list):
            return rows

    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        return data

    rows = []

    def walk(node):
        if isinstance(node, dict):
            if "values" in node and isinstance(node["values"], list):
                rows.append(node["values"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return rows


def get_value(row, index, *keys):
    if isinstance(row, dict):
        for key in keys:
            if key in row:
                return row[key]
        return ""
    if isinstance(row, (list, tuple)):
        if index is not None and len(row) > index:
            return row[index]
        return ""
    return ""


def safe_str(value):
    if value is None:
        return ""
    return str(value)


def write_csv(filename, headers, rows):
    path = OUTPUT_DIR / filename
    with open(path, "w", newline="", encoding="utf-8", errors="replace") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    return path


# ============================================================
# LOAD DATA
# ============================================================

data = {name: load_json(path) for name, path in FILES.items()}
rows = {name: extract_rows_from_volatility_json(obj) if obj else [] for name, obj in data.items()}

pslist_rows = rows["pslist"]
pstree_rows = rows["pstree"]
psscan_rows = rows["psscan"]
cmdline_rows = rows["cmdline"]
netscan_rows = rows["netscan"]
dlllist_rows = rows["dlllist"]
malfind_rows = rows["malfind"]
hivelist_rows = rows["hivelist"]


# ============================================================
# COLUMN ASSUMPTIONS
# ============================================================
# Volatility JSON rows often come as values without headers.
# For common Windows plugins, these positions are usually stable enough
# for teaching summaries, but the script also keeps raw rows in CSV.

# windows.pslist typical:
# PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64,
# CreateTime, ExitTime, File output
#
# windows.netscan typical:
# Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
#
# windows.cmdline typical:
# PID, Process, Args
#
# windows.dlllist typical:
# PID, Process, Base, Size, Name, Path, LoadTime, File output
#
# windows.malfind typical:
# PID, Process, Start VPN, End VPN, Tag, Protection, CommitCharge, PrivateMemory, File output, Hexdump, Disasm


# ============================================================
# PROCESS ANALYSIS
# ============================================================

processes = []

for row in pslist_rows:
    pid = get_value(row, 0, "PID")
    ppid = get_value(row, 1, "PPID")
    name = get_value(row, 2, "ImageFileName", "Process", "Name")
    threads = get_value(row, 4, "Threads")
    handles = get_value(row, 5, "Handles")
    session = get_value(row, 6, "SessionId", "Session", "SessionID")
    wow64 = get_value(row, 7, "Wow64", "WoW64")
    create_time = get_value(row, 8, "CreateTime", "Create Time")
    exit_time = get_value(row, 9, "ExitTime", "Exit Time")

    processes.append({
        "pid": safe_str(pid),
        "ppid": safe_str(ppid),
        "name": safe_str(name),
        "threads": safe_str(threads),
        "handles": safe_str(handles),
        "session": safe_str(session),
        "wow64": safe_str(wow64),
        "create_time": safe_str(create_time),
        "exit_time": safe_str(exit_time),
        "raw": row,
    })


process_name_counts = Counter(p["name"].lower() for p in processes if p["name"])
repeated_processes = process_name_counts.most_common()

# Higher handle/thread count can indicate busy or important processes
def to_int(x):
    try:
        return int(str(x))
    except Exception:
        return 0

top_by_threads = sorted(processes, key=lambda p: to_int(p["threads"]), reverse=True)[:20]
top_by_handles = sorted(processes, key=lambda p: to_int(p["handles"]), reverse=True)[:20]


# ============================================================
# COMMAND-LINE ANALYSIS
# ============================================================

cmdlines = []

for row in cmdline_rows:
    pid = get_value(row, 0, "PID")
    process = get_value(row, 1, "Process", "ImageFileName")
    args = get_value(row, 2, "Args", "CommandLine", "CmdLine", "Command Line")

    cmdlines.append({
        "pid": safe_str(pid),
        "process": safe_str(process),
        "args": safe_str(args),
        "raw": row,
    })


suspicious_keywords = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "curl",
    "wget",
    "encodedcommand",
    "-enc",
    "downloadstring",
    "invoke-expression",
    "iex",
    "temp",
    "appdata",
    "startup",
    "schtasks",
    "net user",
    "whoami",
    "taskkill",
    "vssadmin",
]

suspicious_cmdlines = []

for item in cmdlines:
    combined = f"{item['process']} {item['args']}".lower()
    hits = [kw for kw in suspicious_keywords if kw in combined]
    if hits:
        suspicious_cmdlines.append({
            "pid": item["pid"],
            "process": item["process"],
            "args": item["args"],
            "hits": ", ".join(hits),
        })


# ============================================================
# NETWORK ANALYSIS
# ============================================================

network_entries = []

for row in netscan_rows:
    offset = get_value(row, 0, "Offset")
    proto = get_value(row, 1, "Proto")
    local_addr = get_value(row, 2, "LocalAddr", "Local Address")
    local_port = get_value(row, 3, "LocalPort", "Local Port")
    foreign_addr = get_value(row, 4, "ForeignAddr", "Foreign Address")
    foreign_port = get_value(row, 5, "ForeignPort", "Foreign Port")
    state = get_value(row, 6, "State")
    pid = get_value(row, 7, "PID")
    owner = get_value(row, 8, "Owner")
    created = get_value(row, 9, "Created", "CreateTime", "Create Time")

    network_entries.append({
        "pid": safe_str(pid),
        "owner": safe_str(owner),
        "proto": safe_str(proto),
        "local_addr": safe_str(local_addr),
        "local_port": safe_str(local_port),
        "foreign_addr": safe_str(foreign_addr),
        "foreign_port": safe_str(foreign_port),
        "state": safe_str(state),
        "created": safe_str(created),
        "raw": row,
    })


network_by_pid = Counter(n["pid"] for n in network_entries if n["pid"])
network_by_owner = Counter(n["owner"].lower() for n in network_entries if n["owner"])

external_network_entries = []
for n in network_entries:
    foreign = n["foreign_addr"]
    if foreign and foreign not in ["0.0.0.0", "::", "*", "127.0.0.1", "::1"]:
        external_network_entries.append(n)

external_by_pid = Counter(n["pid"] for n in external_network_entries if n["pid"])


# ============================================================
# DLL ANALYSIS
# ============================================================

dll_by_pid = Counter()
dll_by_process = Counter()

for row in dlllist_rows:
    pid = safe_str(get_value(row, 0, "PID"))
    process = safe_str(get_value(row, 1, "Process", "ImageFileName"))

    if pid:
        dll_by_pid[pid] += 1
    if process:
        dll_by_process[process.lower()] += 1


# ============================================================
# MALFIND ANALYSIS
# ============================================================

malfind_entries = []

for row in malfind_rows:
    pid = get_value(row, 0, "PID")
    process = get_value(row, 1, "Process", "ImageFileName")
    start_vpn = get_value(row, 2, "Start VPN", "Start")
    end_vpn = get_value(row, 3, "End VPN", "End")
    protection = get_value(row, 5, "Protection")

    malfind_entries.append({
        "pid": safe_str(pid),
        "process": safe_str(process),
        "start_vpn": safe_str(start_vpn),
        "end_vpn": safe_str(end_vpn),
        "protection": safe_str(protection),
        "raw": row,
    })

malfind_by_process = Counter(m["process"].lower() for m in malfind_entries if m["process"])
malfind_by_pid = Counter(m["pid"] for m in malfind_entries if m["pid"])


# ============================================================
# BASIC SUSPICION SCORING
# ============================================================

process_index = {p["pid"]: p for p in processes}

scores = defaultdict(int)
reasons = defaultdict(list)

# Repeated process names are not always malicious, but unusual repetition can be interesting
for name, count in process_name_counts.items():
    if count >= 5:
        for p in processes:
            if p["name"].lower() == name:
                scores[p["pid"]] += 1
                reasons[p["pid"]].append(f"Repeated process name appears {count} times")

# High network activity
for pid, count in network_by_pid.items():
    if count >= 5:
        scores[pid] += 2
        reasons[pid].append(f"High number of network entries: {count}")

# External network activity
for pid, count in external_by_pid.items():
    if count >= 1:
        scores[pid] += 1
        reasons[pid].append(f"External/remote network entries: {count}")

# Suspicious command lines
for item in suspicious_cmdlines:
    pid = item["pid"]
    scores[pid] += 3
    reasons[pid].append(f"Suspicious command-line keywords: {item['hits']}")

# Malfind entries
for pid, count in malfind_by_pid.items():
    scores[pid] += 5
    reasons[pid].append(f"Malfind suspicious memory regions: {count}")

# Very high handles/threads
for p in processes:
    if to_int(p["handles"]) >= 1000:
        scores[p["pid"]] += 1
        reasons[p["pid"]].append(f"High handle count: {p['handles']}")
    if to_int(p["threads"]) >= 100:
        scores[p["pid"]] += 1
        reasons[p["pid"]].append(f"High thread count: {p['threads']}")

ranked_suspicious = sorted(scores.items(), key=lambda x: x[1], reverse=True)


# ============================================================
# WRITE CSV TABLES
# ============================================================

write_csv(
    "01_processes.csv",
    ["PID", "PPID", "Process", "Threads", "Handles", "Session", "Wow64", "CreateTime", "ExitTime"],
    [[p["pid"], p["ppid"], p["name"], p["threads"], p["handles"], p["session"], p["wow64"], p["create_time"], p["exit_time"]] for p in processes]
)

write_csv(
    "02_repeated_process_names.csv",
    ["ProcessName", "Count"],
    [[name, count] for name, count in repeated_processes]
)

write_csv(
    "03_top_processes_by_threads.csv",
    ["PID", "Process", "Threads", "Handles", "CreateTime"],
    [[p["pid"], p["name"], p["threads"], p["handles"], p["create_time"]] for p in top_by_threads]
)

write_csv(
    "04_top_processes_by_handles.csv",
    ["PID", "Process", "Handles", "Threads", "CreateTime"],
    [[p["pid"], p["name"], p["handles"], p["threads"], p["create_time"]] for p in top_by_handles]
)

write_csv(
    "05_network_entries.csv",
    ["PID", "Owner", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "Created"],
    [[n["pid"], n["owner"], n["proto"], n["local_addr"], n["local_port"], n["foreign_addr"], n["foreign_port"], n["state"], n["created"]] for n in network_entries]
)

write_csv(
    "06_network_count_by_pid.csv",
    ["PID", "NetworkEntryCount"],
    [[pid, count] for pid, count in network_by_pid.most_common()]
)

write_csv(
    "07_suspicious_cmdlines.csv",
    ["PID", "Process", "Hits", "CommandLine"],
    [[x["pid"], x["process"], x["hits"], x["args"]] for x in suspicious_cmdlines]
)

write_csv(
    "08_malfind_entries.csv",
    ["PID", "Process", "StartVPN", "EndVPN", "Protection"],
    [[m["pid"], m["process"], m["start_vpn"], m["end_vpn"], m["protection"]] for m in malfind_entries]
)

write_csv(
    "09_suspicion_ranking.csv",
    ["PID", "Process", "Score", "Reasons"],
    [
        [
            pid,
            process_index.get(pid, {}).get("name", ""),
            score,
            " | ".join(reasons[pid])
        ]
        for pid, score in ranked_suspicious
    ]
)


# ============================================================
# CREATE INVESTIGATION REPORT
# ============================================================

report = []

report.append("# Memory Dump Investigation Report")
report.append("")
report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
report.append(f"Input folder: `{INPUT_DIR}`")
report.append(f"Output folder: `{OUTPUT_DIR}`")
report.append("")

report.append("## 1. High-Level Summary")
report.append("")
report.append(f"- Total active processes from `pslist`: **{len(processes)}**")
report.append(f"- Total process-tree entries: **{len(pstree_rows)}**")
report.append(f"- Total process-scan entries: **{len(psscan_rows)}**")
report.append(f"- Total command-line entries: **{len(cmdlines)}**")
report.append(f"- Total network entries from `netscan`: **{len(network_entries)}**")
report.append(f"- Total external/remote-looking network entries: **{len(external_network_entries)}**")
report.append(f"- Total DLL entries: **{len(dlllist_rows)}**")
report.append(f"- Total suspicious memory regions from `malfind`: **{len(malfind_entries)}**")
report.append(f"- Total registry hives: **{len(hivelist_rows)}**")
report.append("")

report.append("## 2. Most Repeated Process Names")
report.append("")
for name, count in repeated_processes[:20]:
    report.append(f"- `{name}`: {count}")
report.append("")

report.append("## 3. Top Processes by Thread Count")
report.append("")
for p in top_by_threads[:10]:
    report.append(f"- PID `{p['pid']}` | `{p['name']}` | Threads: `{p['threads']}` | Handles: `{p['handles']}`")
report.append("")

report.append("## 4. Top Processes by Handle Count")
report.append("")
for p in top_by_handles[:10]:
    report.append(f"- PID `{p['pid']}` | `{p['name']}` | Handles: `{p['handles']}` | Threads: `{p['threads']}`")
report.append("")

report.append("## 5. Processes with Most Network Entries")
report.append("")
for pid, count in network_by_pid.most_common(15):
    proc_name = process_index.get(pid, {}).get("name", "")
    report.append(f"- PID `{pid}` | `{proc_name}` | Network entries: `{count}`")
report.append("")

report.append("## 6. Suspicious Command Lines")
report.append("")
if suspicious_cmdlines:
    for item in suspicious_cmdlines[:25]:
        report.append(f"- PID `{item['pid']}` | `{item['process']}` | Hits: `{item['hits']}`")
        report.append(f"  - Command: `{item['args']}`")
else:
    report.append("- No suspicious command-line keywords were detected using the current keyword list.")
report.append("")

report.append("## 7. Malfind Suspicious Memory Regions")
report.append("")
if malfind_entries:
    for pid, count in malfind_by_pid.most_common():
        proc_name = process_index.get(pid, {}).get("name", "")
        report.append(f"- PID `{pid}` | `{proc_name}` | Malfind entries: `{count}`")
else:
    report.append("- No malfind entries were detected, or the malfind plugin did not return results.")
report.append("")

report.append("## 8. Suspicion Ranking")
report.append("")
if ranked_suspicious:
    for pid, score in ranked_suspicious[:20]:
        proc_name = process_index.get(pid, {}).get("name", "")
        report.append(f"- PID `{pid}` | `{proc_name}` | Score: `{score}`")
        for reason in reasons[pid]:
            report.append(f"  - {reason}")
else:
    report.append("- No process received a suspicious score using the current rules.")
report.append("")

report.append("## 9. Important Notes")
report.append("")
report.append("- High thread count or handle count does not automatically mean malware.")
report.append("- Repeated process names can be normal. For example, Chrome, Edge, and service hosts often appear many times.")
report.append("- `malfind` results are suspicious, but they still require manual verification.")
report.append("- Network entries from browsers, update services, cloud sync tools, and security tools may be normal.")
report.append("- This report is a triage report, not final proof of compromise.")
report.append("")

report.append("## 10. Generated CSV Files")
report.append("")
for file in sorted(OUTPUT_DIR.glob("*.csv")):
    report.append(f"- `{file.name}`")

report_path = OUTPUT_DIR / "INVESTIGATION_REPORT.md"
report_path.write_text("\n".join(report), encoding="utf-8", errors="replace")


# ============================================================
# PRINT SUMMARY
# ============================================================

print("\n================ INVESTIGATION SUMMARY ================")
print(f"Total processes: {len(processes)}")
print(f"Total process-scan entries: {len(psscan_rows)}")
print(f"Total network entries: {len(network_entries)}")
print(f"Suspicious command lines: {len(suspicious_cmdlines)}")
print(f"Malfind entries: {len(malfind_entries)}")
print(f"Report saved to: {report_path}")
print("=======================================================")

print("\nTop suspicious processes:")
for pid, score in ranked_suspicious[:10]:
    proc_name = process_index.get(pid, {}).get("name", "")
    print(f"PID {pid} | {proc_name} | Score {score} | {'; '.join(reasons[pid])}")

print(f"\nOpen this file:")
print(report_path)