"""Rich terminal output with colour-coded severity, tables, and banner."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lickygit.core.finding import Severity
from lickygit.core.scanner import ScanResult

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "cyan",
    Severity.LOW: "dim white",
}

_BANNER = r"""
  _ _      _          ____ _ _
 | (_) ___| | ___   _/ ___(_) |_
 | | |/ __| |/ / | | | |  _| | __|
 | | | (__|   <| |_| | |_| | | |_
 |_|_|\___|_|\_\\__, |\____|_|\__|
                |___/
  Lick every secret out of your Git history
"""


class TerminalFormatter:
    """Print scan results to the terminal using *Rich*."""

    def __init__(
        self,
        *,
        use_color: bool = True,
        verbose: bool = False,
        show_banner: bool = True,
    ) -> None:
        self.console = Console(force_terminal=use_color, no_color=not use_color)
        self.verbose = verbose
        self.show_banner = show_banner

    # ------------------------------------------------------------------ #

    def format(self, result: ScanResult) -> None:  # noqa: A003
        """Print *result* to the terminal."""
        if self.show_banner:
            self.console.print(Panel(Text(_BANNER, style="bold green"), expand=False))

        # Summary
        counts = result.counts_by_severity
        self.console.print()
        self.console.print(
            f"[bold]Scan complete[/bold] in "
            f"[cyan]{result.scan_duration:.2f}s[/cyan] - "
            f"[dim]{result.total_commits} commits, {result.total_files} files[/dim]"
        )
        msg = (
            f"  [bold red]Critical:[/bold red] {counts['CRITICAL']}  "
            f"[bold yellow]High:[/bold yellow] {counts['HIGH']}  "
            f"[cyan]Medium:[/cyan] {counts['MEDIUM']}  "
            f"[dim]Low:[/dim] {counts['LOW']}"
        )
        if result.suppressed_by_baseline > 0:
            msg += f"  [dim]({result.suppressed_by_baseline} suppressed by baseline)[/dim]"
        self.console.print(msg)
        self.console.print()

        if not result.findings:
            self.console.print("[bold green]No secrets found![/bold green]")
            return

        # Detailed table
        table = Table(
            title=f"Findings ({len(result.findings)})",
            show_lines=True,
            expand=True,
        )
        table.add_column("Severity", width=10)
        table.add_column("Rule", min_width=20)
        table.add_column("File", min_width=20)
        table.add_column("Secret", min_width=15)

        if self.verbose:
            table.add_column("Commit", width=10)
            table.add_column("Author", min_width=12)
            table.add_column("Line", min_width=30)

        for f in result.findings:
            sev_style = _SEVERITY_STYLE.get(f.severity, "")
            row = [
                Text(f.severity.value, style=sev_style),
                f.rule_name,
                f"{f.file_path}" + (f":{f.line_number}" if f.line_number else ""),
                f.redacted_value,
            ]
            if self.verbose:
                row.extend([
                    (f.commit_sha or "N/A")[:8],
                    f.commit_author,
                    f.line_content[:80],
                ])
            table.add_row(*[str(c) if not isinstance(c, Text) else c for c in row])

        self.console.print(table)
