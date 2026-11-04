"""
ThreatLens - Formatted Output Tables
Color-coded Rich tables for displaying forensic and static analysis results.
Completely free of emojis, optimized for enterprise terminal viewing.
"""

from rich.table import Table
from rich.text import Text
from rich import box
from ui.theme import get_severity_style


def create_permissions_table(permissions_data):
    """Create a formatted table for Android permissions analysis."""
    table = Table(
        title="  [PERMISSIONS] Android Manifest & Dangerous Permissions Audit",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Permission Identifier", style="white", min_width=35)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Forensic Implication / Vector", style="dim white", min_width=30)

    for i, perm in enumerate(permissions_data, 1):
        risk = perm.get("risk", "LOW")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        score_text = Text(str(perm.get("score", 0)), style=style)
        table.add_row(str(i), perm.get("name", ""), risk_text, score_text, perm.get("description", ""))
    return table


def create_imports_table(imports_data):
    """Create a formatted table for suspicious Windows API imports."""
    table = Table(
        title="  [IMPORTS] Suspicious Windows API Imports (MITRE ATT&CK Mapped)",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("API Function", style="bold white", min_width=25)
    table.add_column("Module / DLL", style="dim white", width=15)
    table.add_column("Attack Category", style="cyan", width=20)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Weight", justify="center", width=7)

    for i, imp in enumerate(imports_data, 1):
        risk = imp.get("risk", "LOW")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        score_text = Text(str(imp.get("score", 0)), style=style)
        table.add_row(str(i), imp.get("name", ""), imp.get("dll", ""), imp.get("category", ""), risk_text, score_text)
    return table


def create_network_table(network_data):
    """Create a formatted table for extracted network indicators (IPs, ports, URLs)."""
    table = Table(
        title="  [NETWORK] Extracted C2 & Exfiltration Indicators (Zero-FP Pipeline)",
        box=box.ROUNDED, border_style="red", title_style="bold red",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Type", style="cyan", width=8, justify="center")
    table.add_column("Indicator Value", style="bold red", min_width=30)
    table.add_column("Port", style="bold dark_orange", width=8, justify="center")
    table.add_column("Extraction Context", style="dim white", min_width=25)
    table.add_column("Confidence", justify="center", width=12)

    for i, item in enumerate(network_data, 1):
        conf = item.get("confidence", 0)
        if conf >= 80:
            conf_style = "bold red"
        elif conf >= 60:
            conf_style = "bold dark_orange"
        elif conf >= 40:
            conf_style = "bold yellow"
        else:
            conf_style = "dim green"
        conf_text = Text(f"{conf}%", style=conf_style)
        port_str = str(item.get("port", "-")) if item.get("port") else "-"
        table.add_row(str(i), item.get("type", ""), item.get("value", ""), port_str, item.get("context", ""), conf_text)
    return table


def create_sections_table(sections_data):
    """Create a formatted table for PE section analysis."""
    table = Table(
        title="  [SECTIONS] Portable Executable (PE) Section & Entropy Analysis",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("Section", style="bold white", width=12)
    table.add_column("VirtSize", style="white", width=12, justify="right")
    table.add_column("RawSize", style="white", width=12, justify="right")
    table.add_column("Entropy", justify="center", width=10)
    table.add_column("Characteristics", style="dim white", min_width=20)
    table.add_column("Integrity", justify="center", width=14)

    for sec in sections_data:
        entropy = sec.get("entropy", 0)
        if entropy > 7.0:
            ent_style, status = "bold red", Text("[PACKED/CRYPT]", style="bold red")
        elif entropy > 6.5:
            ent_style, status = "bold yellow", Text("[SUSPICIOUS]", style="bold yellow")
        else:
            ent_style, status = "green", Text("[NORMAL]", style="green")
        ent_text = Text(f"{entropy:.4f}", style=ent_style)
        table.add_row(sec.get("name", ""), sec.get("virtual_size", ""), sec.get("raw_size", ""),
                      ent_text, sec.get("flags", ""), status)
    return table


def create_strings_table(strings_data):
    """Create a formatted table for suspicious strings found."""
    table = Table(
        title="  [STRINGS] High-Confidence Suspicious Strings & Artifacts",
        box=box.ROUNDED, border_style="yellow", title_style="bold yellow",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Category", style="cyan", width=15)
    table.add_column("Extracted Artifact", style="white", min_width=40)
    table.add_column("Offset / Location", style="dim", width=18)

    for i, s in enumerate(strings_data[:50], 1):
        table.add_row(str(i), s.get("category", ""), s.get("value", "")[:80], s.get("location", ""))
    return table


def create_yara_table(yara_matches):
    """Create a formatted table for YARA rule matches."""
    table = Table(
        title="  [YARA] Malicious Signature Rule Matches",
        box=box.ROUNDED, border_style="red", title_style="bold red",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Rule Identifier", style="bold white", min_width=25)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Threat Family", style="cyan", width=18)
    table.add_column("Signature Description", style="dim white", min_width=30)

    for i, match in enumerate(yara_matches, 1):
        sev = match.get("severity", "MEDIUM")
        style = get_severity_style(sev)
        sev_text = Text(sev, style=style)
        table.add_row(str(i), match.get("rule", ""), sev_text, match.get("category", ""), match.get("description", ""))
    return table


def create_summary_table(findings):
    """Create a compact summary table of all findings."""
    table = Table(
        title="  [SUMMARY] Comprehensive Threat Metric Summary",
        box=box.ROUNDED, border_style="cyan", title_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Diagnostic Domain", style="bold white", min_width=25)
    table.add_column("Total Flags", justify="center", width=12)
    table.add_column("Peak Severity", justify="center", width=14)

    for cat, data in findings.items():
        count = str(data.get("count", 0))
        risk = data.get("highest_risk", "CLEAN")
        style = get_severity_style(risk)
        risk_text = Text(risk, style=style)
        table.add_row(cat, count, risk_text)
    return table


def create_virustotal_table(vt_result):
    """Create a formatted table for VirusTotal scan results."""
    if vt_result.get("status") != "found":
        return None

    detection_count = vt_result.get("detection_count", 0)
    total = vt_result.get("total_engines", 0)
    detections = vt_result.get("detections", [])

    # Clean / Benign Sample Consensus
    if detection_count == 0:
        table = Table(
            title=f"  [VIRUSTOTAL] Multi-Engine Threat Intelligence (0/{total} Flagged — Verified Clean)",
            box=box.ROUNDED, border_style="bold green", title_style="bold green",
            show_lines=True, padding=(0, 1),
        )
        table.add_column("Status", style="bold green", justify="center", width=12)
        table.add_column("Consensus Details", style="bold white", min_width=35)
        table.add_column("Community Reputation", style="dim cyan", min_width=25)
        table.add_column("Verdict", justify="center", width=14)

        rep = vt_result.get("file_info", {}).get("reputation", 0)
        rep_text = f"+{rep}" if rep > 0 else str(rep)
        table.add_row(
            "[OK] CLEAN",
            f"0 of {total} commercial security engines detected malicious signatures",
            f"Global VT Reputation Score: {rep_text}",
            Text("BENIGN", style="bold green")
        )
        return table

    # Flagged Sample Table
    border_col = "bold red" if detection_count >= 5 else "bold yellow"
    table = Table(
        title=f"  [VIRUSTOTAL] Multi-Engine Threat Intelligence ({detection_count}/{total} Flagged)",
        box=box.ROUNDED, border_style=border_col, title_style=border_col,
        show_lines=True, padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Security Engine", style="bold white", min_width=22)
    table.add_column("Malware Classification", style="bold red", min_width=30)
    table.add_column("Verdict", justify="center", width=14)

    for i, det in enumerate(detections[:25], 1):
        cat = det.get("category", "")
        cat_style = "bold red" if cat == "malicious" else "bold yellow"
        cat_text = Text(cat.upper(), style=cat_style)
        table.add_row(str(i), det.get("engine", ""), det.get("result", ""), cat_text)

    return table


def create_heuristics_table(heuristics_data):
    """Create a styled table for Advanced Heuristics and Anti-Analysis."""
    table = Table(
        title=f"  [HEURISTICS] Advanced Heuristics & Anti-Analysis Traces ({len(heuristics_data)})",
        box=box.ROUNDED, border_style="bold red", title_style="bold red",
        show_lines=True, padding=(0, 1)
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Category", style="bold magenta", width=16)
    table.add_column("Detection Trace", style="bold white", min_width=30)
    table.add_column("Location / Artifact", style="dim cyan", min_width=20)
    table.add_column("Risk Level", justify="center", width=12)

    for i, h in enumerate(heuristics_data, 1):
        sev = h.get("severity", "MEDIUM")
        style = get_severity_style(sev)
        sev_text = Text(sev, style=style)
        table.add_row(str(i), h.get("category", ""), h.get("description", ""), h.get("file", ""), sev_text)
    return table


def create_ip_intelligence_table(ip_intel_list):
    """Create a formatted table for Extracted C2 & IP Infrastructure Intelligence."""
    if not ip_intel_list:
        return None

    table = Table(
        title=f"  [INFRASTRUCTURE] Extracted Remote C2 & IP Intelligence ({len(ip_intel_list)} Hosts)",
        box=box.ROUNDED, border_style="bold red", title_style="bold red",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("Remote IP:Port", style="bold white", min_width=20)
    table.add_column("Geo", style="cyan", width=8, justify="center")
    table.add_column("ISP / AS Organization", style="dim white", min_width=24)
    table.add_column("Reverse DNS / Hostname", style="dim cyan", min_width=24)
    table.add_column("VT Flags", style="bold red", justify="center", width=12)
    table.add_column("Verdict", justify="center", width=16)

    for item in ip_intel_list:
        ip = item.get("ip", "")
        port = item.get("port")
        ip_display = f"{ip}:{port}" if port else ip
        if item.get("port_tag"):
            ip_display += f" [{item['port_tag']}]"

        country = item.get("country", "??")
        as_owner = item.get("as_owner", "Unknown")
        rdns = item.get("reverse_dns", "None")
        det_rate = item.get("detection_rate", "0/0")
        
        mal = item.get("malicious_count", 0)
        tags = item.get("tags", [])
        
        if mal >= 5 or "c2" in tags:
            verdict_style = "bold red"
            verdict_text = "CONFIRMED C2"
        elif mal >= 2 or "tor" in tags:
            verdict_style = "bold yellow"
            verdict_text = "TOR / SUSPICIOUS"
        elif mal == 1:
            verdict_style = "yellow"
            verdict_text = "QUESTIONABLE"
        else:
            verdict_style = "bold green"
            verdict_text = "CLEAN HOST"

        table.add_row(
            ip_display,
            country,
            as_owner[:28],
            rdns[:28],
            det_rate,
            Text(verdict_text, style=verdict_style)
        )

    return table
