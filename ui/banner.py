"""
ThreatLens - Terminal Banner & Menu Interface
Professional branding, telemetry status, and interactive navigation without emojis.
"""

import time
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich import box

from ui.theme import COLORS, ICONS

VERSION = "1.0.0"
AUTHOR = "ThreatLens Security Research"
CODENAME = "Sentinel"

BANNER_LOGO = r"""
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗     ███████╗███╗   ██╗███████╗
 ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     █████╗  ██╔██╗ ██║███████╗
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗██║ ╚████║███████║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
"""


def display_banner(console: Console, animated=True):
    """
    Display the ThreatLens executive cyber banner.

    Args:
        console: Rich Console instance.
        animated: Whether to show loading animation.
    """
    console.clear()

    # Main Logo
    banner_text = Text(BANNER_LOGO, style="bold cyan")

    # Header Telemetry Bar
    telemetry_table = Table(box=box.HORIZONTALS, border_style="dim cyan", show_header=False, expand=True)
    telemetry_table.add_column("Key", style="dim cyan", justify="left")
    telemetry_table.add_column("Value", style="bold white", justify="right")
    
    telemetry_table.add_row(
        "[SEC] ADVANCED MALICIOUS APK & PE/EXE STATIC TRIAGE ENGINE",
        f"CORE: v{VERSION} [{CODENAME}]"
    )
    telemetry_table.add_row(
        "HEURISTICS: Anti-VM | Anti-Debug | Evasion | Zero-FP Network",
        "STATUS: ONLINE [ZERO-FP ACTIVE]"
    )

    console.print(banner_text)
    console.print(telemetry_table)
    console.print()

    if animated:
        _animated_startup(console)


def _animated_startup(console: Console):
    """Show an animated startup sequence without emojis."""
    modules = [
        ("Initializing static disassembly engine", "[OK]"),
        ("Loading YARA rule database (15+ malware families)", "[OK]"),
        ("Indexing suspicious Win32 / Native API signatures", "[OK]"),
        ("Auditing dangerous Android permission matrix", "[OK]"),
        ("Mounting local autonomous threat intelligence vault", "[OK]"),
        ("System operational and ready for sample ingestion", "[READY]"),
    ]

    for label, status_tag in modules:
        console.print(
            f"  [dim cyan]>>[/] [dim white]{label:<58}[/] ", end=""
        )
        time.sleep(0.08)
        tag_color = "bold green" if "OK" in status_tag else "bold cyan"
        console.print(f"[{tag_color}]{status_tag}[/]")

    console.print()


def display_disclaimer(console: Console):
    """Display the legal disclaimer without emojis."""
    disclaimer = (
        "[bold yellow][LEGAL NOTICE][/bold yellow] "
        "[dim white]ThreatLens is engineered exclusively for authorized security analysis, "
        "malware research, and educational triage. Unauthorized reverse engineering or "
        "inspection of binaries without explicit owner permission is strictly prohibited. "
        "The developers assume no liability for misuse.[/dim white]"
    )

    console.print(
        Panel(
            disclaimer,
            border_style="dim yellow",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


def display_menu(console: Console):
    """Display the main interactive menu in an attractive executive cyber table."""
    menu_table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        title="[bold cyan]SYSTEM OPERATIONS / CONTROL CONSOLE[/]",
        title_align="center",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    menu_table.add_column("Key", style="bold cyan", justify="center", width=7)
    menu_table.add_column("Operation", style="bold white", width=26)
    menu_table.add_column("Scope & Diagnostic Target", style="dim white")

    menu_table.add_row("[ 1 ]", "APK Analysis", "Android DEX, AndroidManifest, Permissions & Native Libs")
    menu_table.add_row("[ 2 ]", "PE / EXE Analysis", "Windows PE Headers, Section Entropies & MITRE ATT&CK APIs")
    menu_table.add_row("[ 3 ]", "Batch Directory Scan", "Recursive automated triage across sample directories")
    menu_table.add_row("[ 4 ]", "Threat Intelligence Vault", "Query offline learned database & historical JSON reports")
    menu_table.add_row("[ 5 ]", "System Diagnostics", "Engine dependencies, signature rulesets & API config")
    menu_table.add_row("[ 6 ]", "Terminate Session", "Safely unmount engines and exit ThreatLens")

    console.print(menu_table)
