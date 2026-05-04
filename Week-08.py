import subprocess
import json
from pathlib import Path
from datetime import datetime


# ============================================================
# CONFIGURATION
# Change these paths only if your folders are different
# ============================================================

VOL_EXE = r"C:\Users\munee\AppData\Local\Schrodinger\PyMOL2\envs\n8n-env\Scripts\vol.exe"

MEMORY_IMAGE = r"C:\Users\munee\Desktop\PhD\Teaching\TECH5200\RAMCapture\memdump-001.mem"

OUTPUT_DIR = Path(r"C:\Users\munee\Desktop\PhD\Teaching\TECH5200\VolatilityPythonOverview")
OUTPUT_DIR.mkdir(exist_ok=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def run_volatility(plugin, output_name, renderer="json"):
    """
    Runs a Volatility 3 plugin and saves the raw output.
    Uses JSON renderer by default because it is easier to parse.
    """
    output_file = OUTPUT_DIR / output_name

    command = [
        VOL_EXE,
        "-f", MEMORY_IMAGE,
        "-r", renderer,
        plugin
    ]

    print(f"[RUNNING] {plugin}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            check=False
        )

        output_file.write_text(result.stdout, encoding="utf-8", errors="replace")

        if result.stderr.strip():
            error_file = OUTPUT_DIR / f"{output_name}.stderr.txt"
            error_file.write_text(result.stderr, encoding="utf-8", errors="replace")

        if result.returncode != 0:
            print(f"[WARNING] {plugin} returned code {result.returncode}")

        return result.stdout

    except Exception as e:
        print(f"[ERROR] Could not run {plugin}: {e}")
        return ""


def parse_json_output(raw_text):
    """
    Parses Volatility JSON output safely.
    """
    try:
        data = json.loads(raw_text)
        return data
    except Exception:
        return None


def extract_rows(json_data):
    """
    Volatility JSON usually stores data in a tree/grid-like structure.
    This function tries to extract rows safely.
    """
    if not json_data:
        return []

    if isinstance(json_data, dict):
        rows = json_data.get("rows")
        if isinstance(rows, list):
            return rows

    if isinstance(json_data, list) and all(isinstance(item, dict) for item in json_data):
        return json_data

    rows = []

    def walk(node):
        if isinstance(node, dict):
            if "values" in node:
                rows.append(node["values"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json_data)
    return rows


# ============================================================
# RUN VOLATILITY PLUGINS
# ============================================================

plugins = {
    "windows.info.Info": "01_windows_info.json",
    "windows.pslist.PsList": "02_pslist.json",
    "windows.pstree.PsTree": "03_pstree.json",
    "windows.psscan.PsScan": "03b_psscan.json",
    "windows.cmdline.CmdLine": "04_cmdline.json",
    "windows.netscan.NetScan": "05_netscan.json",
    "windows.dlllist.DllList": "06_dlllist.json",
    "windows.malware.malfind.Malfind": "07_malfind.json",
    "windows.registry.hivelist.HiveList": "08_hivelist.json",
}

raw_outputs = {}

for plugin, filename in plugins.items():
    raw_outputs[plugin] = run_volatility(plugin, filename)


# ============================================================
# PARSE RESULTS
# ============================================================

summary = {}

# Process list
pslist_json = parse_json_output(raw_outputs.get("windows.pslist.PsList", ""))
pslist_rows = extract_rows(pslist_json)
summary["number_of_processes"] = len(pslist_rows)

# Process tree
pstree_json = parse_json_output(raw_outputs.get("windows.pstree.PsTree", ""))
pstree_rows = extract_rows(pstree_json)
summary["number_of_process_tree_entries"] = len(pstree_rows)

# Process scan (carves EPROCESS from memory)
psscan_json = parse_json_output(raw_outputs.get("windows.psscan.PsScan", ""))
psscan_rows = extract_rows(psscan_json)
summary["number_of_process_scan_entries"] = len(psscan_rows)

# Command lines
cmdline_json = parse_json_output(raw_outputs.get("windows.cmdline.CmdLine", ""))
cmdline_rows = extract_rows(cmdline_json)
summary["number_of_command_line_entries"] = len(cmdline_rows)

# Network connections
netscan_json = parse_json_output(raw_outputs.get("windows.netscan.NetScan", ""))
netscan_rows = extract_rows(netscan_json)
summary["number_of_network_entries"] = len(netscan_rows)

# DLL list
dlllist_json = parse_json_output(raw_outputs.get("windows.dlllist.DllList", ""))
dlllist_rows = extract_rows(dlllist_json)
summary["number_of_dll_entries"] = len(dlllist_rows)

# Malfind
malfind_json = parse_json_output(raw_outputs.get("windows.malware.malfind.Malfind", ""))
malfind_rows = extract_rows(malfind_json)
summary["number_of_malfind_entries"] = len(malfind_rows)

# Registry hives
hivelist_json = parse_json_output(raw_outputs.get("windows.registry.hivelist.HiveList", ""))
hivelist_rows = extract_rows(hivelist_json)
summary["number_of_registry_hives"] = len(hivelist_rows)


# ============================================================
# CREATE HUMAN-READABLE REPORT
# ============================================================

report_lines = []

report_lines.append("# Volatility 3 Memory Forensics Overview")
report_lines.append("")
report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
report_lines.append(f"Memory image: `{MEMORY_IMAGE}`")
report_lines.append("")
report_lines.append("## Summary")
report_lines.append("")
report_lines.append(f"- Number of processes: {summary['number_of_processes']}")
report_lines.append(f"- Number of process-tree entries: {summary['number_of_process_tree_entries']}")
report_lines.append(f"- Number of process-scan entries: {summary['number_of_process_scan_entries']}")
report_lines.append(f"- Number of command-line entries: {summary['number_of_command_line_entries']}")
report_lines.append(f"- Number of network entries: {summary['number_of_network_entries']}")
report_lines.append(f"- Number of DLL entries: {summary['number_of_dll_entries']}")
report_lines.append(f"- Number of suspicious memory regions from malfind: {summary['number_of_malfind_entries']}")
report_lines.append(f"- Number of registry hives: {summary['number_of_registry_hives']}")
report_lines.append("")

report_lines.append("## Interpretation Guide")
report_lines.append("")
report_lines.append("### Processes")
report_lines.append("`windows.pslist.PsList` shows active processes found through the normal Windows process list.")
report_lines.append("")
report_lines.append("### Process Tree")
report_lines.append("`windows.pstree.PsTree` shows parent-child relationships between processes.")
report_lines.append("")
report_lines.append("### Process Scan")
report_lines.append("`windows.psscan.PsScan` scans memory to recover processes that may not appear in the active list.")
report_lines.append("")
report_lines.append("### Command Lines")
report_lines.append("`windows.cmdline.CmdLine` shows how processes were launched.")
report_lines.append("")
report_lines.append("### Network Connections")
report_lines.append("`windows.netscan.NetScan` shows network sockets and connections found in memory.")
report_lines.append("")
report_lines.append("### DLLs")
report_lines.append("`windows.dlllist.DllList` shows DLLs loaded by processes.")
report_lines.append("")
report_lines.append("### Malfind")
report_lines.append("`windows.malware.malfind.Malfind` highlights memory regions that may contain injected or suspicious code.")
report_lines.append("")
report_lines.append("### Registry Hives")
report_lines.append("`windows.registry.hivelist.HiveList` shows registry hives present in memory.")
report_lines.append("")

report_lines.append("## Output Files")
report_lines.append("")
for plugin, filename in plugins.items():
    report_lines.append(f"- `{filename}` generated by `{plugin}`")

report_text = "\n".join(report_lines)

report_path = OUTPUT_DIR / "memory_forensics_overview.md"
report_path.write_text(report_text, encoding="utf-8", errors="replace")

summary_json_path = OUTPUT_DIR / "summary_counts.json"
summary_json_path.write_text(json.dumps(summary, indent=4), encoding="utf-8")


# ============================================================
# PRINT FINAL SUMMARY
# ============================================================

print("\n================ MEMORY FORENSICS SUMMARY ================")
print(f"Processes: {summary['number_of_processes']}")
print(f"Process tree entries: {summary['number_of_process_tree_entries']}")
print(f"Process scan entries: {summary['number_of_process_scan_entries']}")
print(f"Command-line entries: {summary['number_of_command_line_entries']}")
print(f"Network entries: {summary['number_of_network_entries']}")
print(f"DLL entries: {summary['number_of_dll_entries']}")
print(f"Malfind suspicious entries: {summary['number_of_malfind_entries']}")
print(f"Registry hives: {summary['number_of_registry_hives']}")
print("===========================================================")

print(f"\nReport saved to:")
print(report_path)

print(f"\nAll raw outputs saved in:")
print(OUTPUT_DIR)