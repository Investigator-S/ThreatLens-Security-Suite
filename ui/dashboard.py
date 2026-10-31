"""
ThreatLens - Dashboard Interface
High-tech visual telemetry, segmented gauges, and progress indicators without emojis.
"""

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from ui.theme import ICONS, get_severity_for_score


def create_progress_bar():
    """Create a styled progress bar for scan phases."""
    return Progress(
        SpinnerColumn(spinner_name="dots12", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=True,
    )


def create_status_spinner(console, message):
    """Create a high-tech status spinner."""
    return console.status(
        f"[bold cyan]>> {message}...",
        spinner="dots12",
        spinner_style="bold cyan"
    )


def display_scan_header(console, file_info, file_type):
    """Display the scan target metadata in a structured cyber panel."""
    size_bytes = file_info.get("size_bytes", 0)
    if size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.2f} KB ({size_bytes:,} bytes)"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB ({size_bytes:,} bytes)"

    header_table = Table(box=None, show_header=False, padding=(0, 2))
    header_table.add_column("Property", style="dim cyan", width=18)
    header_table.add_column("Value", style="bold white")

    header_table.add_row("Artifact Name", file_info.get("filename", "Unknown"))
    header_table.add_row("Target Architecture", f"{file_type}")
    header_table.add_row("Payload Size", size_str)
    header_table.add_row("Filesystem Path", file_info.get("filepath", "N/A"))

    console.print(
        Panel(
            header_table,
            title="[bold cyan][TARGET SPECIFICATION][/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    )


def display_hash_info(console, hashes):
    """Display cryptographic file hash digests."""
    hash_table = Table(box=box.SIMPLE_HEAD, border_style="dim cyan", show_header=True, padding=(0, 1))
    hash_table.add_column("Algorithm", style="bold cyan", width=12)
    hash_table.add_column("Digest Signature", style="bold white")

    for algo, value in hashes.items():
        hash_table.add_row(algo.upper(), str(value))

    console.print(
        Panel(
            hash_table,
            title="[bold cyan][CRYPTOGRAPHIC FINGERPRINTS][/]",
            border_style="dim cyan",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    )


def display_threat_score(console, score, breakdown=None):
    """Display the overall threat score with an advanced visual gauge and categorical breakdown."""
    severity, config = get_severity_for_score(score)
    bar_width = 44
    filled = max(0, min(bar_width, int((score / 100) * bar_width)))
    unfilled = bar_width - filled

    if score >= 80:
        bar_color = "bold red"
        badge = "[ CRITICAL THREAT ]"
    elif score >= 60:
        bar_color = "bold dark_orange"
        badge = "[ HIGH RISK ]"
    elif score >= 40:
        bar_color = "bold yellow"
        badge = "[ ELEVATED RISK ]"
    elif score >= 20:
        bar_color = "cyan"
        badge = "[ LOW RISK ]"
    else:
        bar_color = "bold green"
        badge = "[ CLEAN / BENIGN ]"

    score_panel_text = Text()
    score_panel_text.append("\n  THREAT INTELLIGENCE COMPOSITE SCORE\n", style="bold white")
    score_panel_text.append(f"  {'=' * 62}\n\n", style="dim cyan")
    score_panel_text.append("  Score: ", style="dim white")
    score_panel_text.append(f"{score}/100", style=bar_color)
    score_panel_text.append("   Classification: ", style="dim white")
    score_panel_text.append(f"{badge}\n\n", style=bar_color)

    # Meter bar
    score_panel_text.append("  [", style="dim cyan")
    score_panel_text.append("█" * filled, style=bar_color)
    score_panel_text.append("░" * unfilled, style="dim white")
    score_panel_text.append(f"]  {score}%\n\n", style="bold white")

    if breakdown:
        score_panel_text.append("  Categorical Risk Breakdown:\n", style="bold white")
        for cat, pts in breakdown.items():
            if pts > 0:
                score_panel_text.append(f"    * {cat:<32} +{pts:>2} pts\n", style=bar_color)
            else:
                score_panel_text.append(f"    * {cat:<32}    0 pts\n", style="dim")

    console.print(
        Panel(
            score_panel_text,
            title=f"[{bar_color}]=== THREAT ASSESSMENT MATRIX ===[/]",
            title_align="center",
            border_style=bar_color.split()[-1],
            box=box.DOUBLE_EDGE,
            padding=(0, 1)
        )
    )


def display_section_header(console, title, icon=""):
    """Display a section header with cyber styling and zero emojis."""
    console.print()
    tag = f"{icon} " if icon else ">> "
    console.print(f"  [bold cyan]{tag}{title}[/]")
    console.print(f"  [dim cyan]{'-' * 64}[/]")
