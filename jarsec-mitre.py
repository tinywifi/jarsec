#!/usr/bin/env python3
"""
Jarsec MITRE ATT&CK Mapper — auto-tags analysis findings with MITRE techniques.

Usage:
    python3 jarsec-mitre.py /path/to/workspace

Reads agent reports from workspace and outputs:
    - mitre_techniques.json (structured mapping)
    - mitre_summary.txt (human-readable)

Supports MITRE ATT&CK v14.1 techniques for Enterprise matrix.
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# ── MITRE Technique Mapping ─────────────────────────────────────────────────

TECHNIQUES = {
    # Initial Access
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),

    # Execution
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1059.005": ("Visual Basic", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1053": ("Scheduled Task/Job", "Execution"),
    "T1204": ("User Execution", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1106": ("Native API", "Execution"),

    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1547.001": ("Registry Run Keys", "Persistence"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1546": ("Event Triggered Execution", "Persistence"),

    # Privilege Escalation
    "T1055": ("Process Injection", "Privilege Escalation"),
    "T1055.012": ("Process Hollowing", "Privilege Escalation"),
    "T1078": ("Valid Accounts", "Privilege Escalation"),

    # Defense Evasion
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1027.004": ("Compile After Delivery", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1070.006": ("Timestomp", "Defense Evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1497.001": ("System Checks", "Defense Evasion"),
    "T1622": ("Debugger Evasion", "Defense Evasion"),
    "T1553": ("Subvert Trust Controls", "Defense Evasion"),
    "T1553.004": ("Install Root Certificate", "Defense Evasion"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),

    # Credential Access
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1056": ("Input Capture", "Credential Access"),
    "T1056.001": ("Keylogging", "Credential Access"),

    # Discovery
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1518": ("Software Discovery", "Discovery"),
    "T1518.001": ("Security Software Discovery", "Discovery"),
    "T1080": ("Taint Shared Content", "Discovery"),

    # Lateral Movement
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.005": ("VNC", "Lateral Movement"),
    "T1021.006": ("Windows Remote Management", "Lateral Movement"),

    # Collection
    "T1560": ("Archive Collected Data", "Collection"),
    "T1005": ("Data from Local System", "Collection"),
    "T1074": ("Data Staged", "Collection"),
    "T1113": ("Screen Capture", "Collection"),
    "T1123": ("Audio Capture", "Collection"),
    "T1125": ("Video Capture", "Collection"),
    "T1114": ("Email Collection", "Collection"),

    # Command and Control
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.002": ("File Transfer Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1573.002": ("Asymmetric Cryptography", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1219": ("Remote Access Software", "Command and Control"),

    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1048.001": ("Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1567.001": ("Exfiltration to Code Repository", "Exfiltration"),
    "T1567.002": ("Exfiltration to Cloud Storage", "Exfiltration"),

    # Impact
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1491": ("Defacement", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
}

# Keyword → technique IDs mapping
KEYWORD_MAP = {
    # Token/session theft
    "token": ["T1539", "T1552"],
    "session": ["T1539", "T1552"],
    "credential": ["T1539", "T1552", "T1003"],
    "steal": ["T1539", "T1005"],
    "grab": ["T1539", "T1005"],
    "password": ["T1552", "T1003"],
    "cookie": ["T1539"],

    # C2 / Exfiltration
    "webhook": ["T1041", "T1071.001"],
    "discord": ["T1041", "T1071.001"],
    "telegram": ["T1041", "T1071.001"],
    "exfil": ["T1041", "T1048"],
    "ethereum": ["T1071.001", "T1041"],
    "blockchain": ["T1071.001", "T1041"],
    "rpc": ["T1071.001"],
    "c2": ["T1071", "T1071.001"],
    "command and control": ["T1071"],

    # Execution
    "processbuilder": ["T1059", "T1059.003"],
    "runtime.exec": ["T1059", "T1059.003"],
    "exec": ["T1059"],
    "shell": ["T1059", "T1059.003", "T1059.004"],
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "commandline": ["T1059"],

    # Process injection / Stage-2
    "urlclassloader": ["T1055", "T1620"],
    "defineclass": ["T1055", "T1620"],
    "classloader": ["T1055", "T1055.012", "T1620"],
    "inject": ["T1055"],
    "stage-2": ["T1055", "T1105"],
    "stage2": ["T1055", "T1105"],
    "dropper": ["T1055", "T1105"],
    "payload": ["T1055", "T1105"],
    "hollow": ["T1055.012"],
    "reflective": ["T1620"],

    # Obfuscation / Defense Evasion
    "obfusc": ["T1027", "T1027.002"],
    "packer": ["T1027.002"],
    "encrypt": ["T1027"],
    "decrypt": ["T1027"],
    "xor": ["T1027"],
    "jnic": ["T1027", "T1497"],
    "anti-debug": ["T1497", "T1622"],
    "anti-vm": ["T1497", "T1497.001"],
    "sandbox": ["T1497", "T1497.001"],
    "trustmanager": ["T1553.004"],
    "ssl bypass": ["T1553.004"],
    "certificate": ["T1553.004"],
    "log scrub": ["T1070", "T1070.004"],

    # Persistence
    "registry": ["T1547", "T1547.001"],
    "autostart": ["T1547"],
    "startup": ["T1547"],
    "scheduled task": ["T1053"],
    "schtasks": ["T1053"],
    "cron": ["T1053"],
    "javaagent": ["T1546"],

    # Collection
    "clipboard": ["T1115"],
    "screen capture": ["T1113"],
    "webcam": ["T1125"],
    "microphone": ["T1123"],
    "screenshot": ["T1113"],
    "keylog": ["T1056.001"],
    "keystroke": ["T1056.001"],

    # Network discovery
    "port scan": ["T1046"],
    "network": ["T1016", "T1046"],
    "inetaddress": ["T1016"],

    # Mixin / Code injection
    "mixin": ["T1055", "T1620"],
    "@inject": ["T1055", "T1620"],
    "@redirect": ["T1055", "T1620"],

    # Viral propagation
    "jarfile": ["T1055", "T1105"],
    "zipinputstream": ["T1055", "T1105"],
    "self-replic": ["T1055", "T1105"],
    "propagat": ["T1055", "T1105"],
}


def map_keywords_to_techniques(text: str) -> dict:
    """Map free-text findings to MITRE technique IDs."""
    text_lower = text.lower()
    matched = defaultdict(list)

    for keyword, techniques in KEYWORD_MAP.items():
        if keyword in text_lower:
            for tid in techniques:
                if tid in TECHNIQUES:
                    name, tactic = TECHNIQUES[tid]
                    matched[tid].append({
                        "name": name,
                        "tactic": tactic,
                        "matched_keyword": keyword,
                    })

    return dict(matched)


def read_agent_reports(workspace: Path) -> str:
    """Read all agent report files from workspace."""
    combined = []
    for report_file in workspace.glob("agent_*.txt"):
        try:
            text = report_file.read_text(errors="replace")
            combined.append(text)
        except Exception:
            continue

    # Also read decrypted/extracted strings
    for txt_file in ["decrypted_strings.txt", "extracted_strings.txt", "fs_events.log"]:
        path = workspace / txt_file
        if path.exists():
            try:
                combined.append(path.read_text(errors="replace"))
            except Exception:
                continue

    return "\n".join(combined)


def generate_mitre_report(workspace: Path) -> dict:
    """Generate MITRE technique mapping from workspace."""
    text = read_agent_reports(workspace)
    techniques = map_keywords_to_techniques(text)

    # Build structured output
    tactics = defaultdict(list)
    for tid, entries in techniques.items():
        name, tactic = TECHNIQUES[tid]
        tactics[tactic].append({
            "technique_id": tid,
            "technique_name": name,
            "matched_keywords": list(set(e["matched_keyword"] for e in entries)),
        })

    return {
        "tactics": dict(tactics),
        "techniques": {
            tid: {
                "name": TECHNIQUES[tid][0],
                "tactic": TECHNIQUES[tid][1],
                "matched_keywords": list(set(e["matched_keyword"] for e in entries)),
            }
            for tid, entries in techniques.items()
        },
        "total_techniques": len(techniques),
        "total_tactics": len(tactics),
    }


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/workspace")
        sys.exit(1)

    workspace = Path(sys.argv[1])
    if not workspace.exists():
        print(f"Error: {workspace} does not exist")
        sys.exit(1)

    report = generate_mitre_report(workspace)

    # Write JSON
    json_path = workspace / "mitre_techniques.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # Write human-readable summary
    txt_path = workspace / "mitre_summary.txt"
    with open(txt_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("MITRE ATT&CK TECHNIQUE MAPPING\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total Techniques: {report['total_techniques']}\n")
        f.write(f"Total Tactics: {report['total_tactics']}\n\n")

        for tactic, techniques in sorted(report["tactics"].items()):
            f.write(f"\n{tactic.upper()}\n")
            f.write("-" * 40 + "\n")
            for t in techniques:
                f.write(f"  {t['technique_id']} — {t['technique_name']}\n")
                f.write(f"    Keywords: {', '.join(t['matched_keywords'])}\n")

    print(f"MITRE JSON: {json_path}")
    print(f"MITRE Summary: {txt_path}")
    print(f"Techniques: {report['total_techniques']} | Tactics: {report['total_tactics']}")


if __name__ == "__main__":
    main()
