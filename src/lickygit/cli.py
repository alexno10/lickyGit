"""Click-based CLI for lickyGit."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from lickygit.config import ScanConfig, load_config, merge_configs, validate_config
from lickygit.core.finding import Severity
from lickygit.core.git_walker import GitWalker, GitWalkerError, safe_rmtree
from lickygit.core.scanner import ScanResult, Scanner
from lickygit.detection.engine import DetectionEngine
from lickygit.detection.patterns import PatternRule
from lickygit.detection.rules.custom import load_rules_from_toml, load_rules_from_yaml
from lickygit.filters.allowlist import AllowList
from lickygit.filters.path_filter import PathFilter

console = Console(stderr=True)

_SEVERITY_MAP = {s.value.lower(): s for s in Severity}


# ====================================================================== #
# CLI group
# ====================================================================== #

@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """lickyGit - Lick every secret out of your Git history."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ====================================================================== #
# scan command
# ====================================================================== #

@main.command()
@click.argument("repo_path", default=".", type=click.Path(exists=False))
@click.option("--url", "-u", default=None, help="Clone a URL and scan it.")
@click.option("--head-only", "-H", is_flag=True, help="Only scan HEAD, not full history.")
@click.option("--staged", is_flag=True, help="Scan staged changes in Git index (ideal for pre-commit).")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "json", "csv", "sarif", "html", "gitlab"], case_sensitive=False),
    default=None, help="Output format (default: terminal).",
)
@click.option("--output", "-o", "output_file", default=None, type=click.Path(), help="Output file path.")
@click.option("--config", "-c", "config_path", default=None, type=click.Path(exists=True), help="Config file path.")
@click.option("--no-color", is_flag=True, help="Disable coloured output.")
@click.option("--no-banner", is_flag=True, help="Disable the banner.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None, help="Minimum severity to report.",
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None, help="Exit 1 only if findings at this severity or above exist.",
)
@click.option("--since-commit", default=None, help="Only scan commits after this SHA (incremental).")
@click.option("--diff", "diff_base", default=None, help="Only scan commits in DIFF_BASE..HEAD (PR scanning).")
@click.option("--no-entropy", is_flag=True, help="Disable entropy detection.")
@click.option("--no-keywords", is_flag=True, help="Disable keyword detection.")
@click.option("--no-builtin-rules", is_flag=True, help="Disable built-in patterns.")
@click.option("--custom-rules", default=None, type=click.Path(exists=True), help="Custom rules file (TOML/YAML).")
@click.option("--allowlist", default=None, type=click.Path(exists=True), help="Allowlist file path.")
@click.option("--baseline", default=None, type=click.Path(exists=True), help="Path to baseline file to ignore known findings.")
@click.option("--generate-baseline", default=None, type=click.Path(), help="Path to generate baseline JSON file from findings.")
@click.option("--exclude", multiple=True, help="Glob patterns to exclude.")
@click.option("--include", multiple=True, help="Glob patterns to include.")
@click.option("--max-workers", default=None, type=int, help="Thread pool size (default: 4).")
@click.option("--delete", "-d", is_flag=True, help="Delete cloned repo after scan.")
def scan(
    repo_path: str,
    url: str | None,
    head_only: bool,
    staged: bool,
    output_format: str | None,
    output_file: str | None,
    config_path: str | None,
    no_color: bool,
    no_banner: bool,
    verbose: bool,
    severity: str | None,
    fail_on_severity: str | None,
    since_commit: str | None,
    diff_base: str | None,
    no_entropy: bool,
    no_keywords: bool,
    no_builtin_rules: bool,
    custom_rules: str | None,
    allowlist: str | None,
    baseline: str | None,
    generate_baseline: str | None,
    exclude: tuple[str, ...],
    include: tuple[str, ...],
    max_workers: int | None,
    delete: bool,
) -> None:
    """Scan a Git repository for leaked secrets."""
    # ── 1. Load config file ────────────────────────────────────────────
    try:
        file_config = load_config(config_path)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(2)

    # ── 2. Build CLI overrides ─────────────────────────────────────────
    cli: dict[str, object] = {}
    if head_only:
        cli["head_only"] = True
    if staged:
        cli["staged"] = True
    if output_format is not None:
        cli["output_format"] = output_format
    if output_file is not None:
        cli["output_file"] = output_file
    if no_color:
        cli["use_color"] = False
    if no_banner:
        cli["show_banner"] = False
    if verbose:
        cli["verbose"] = True
    if severity is not None:
        cli["min_severity"] = _SEVERITY_MAP[severity.lower()]
    if fail_on_severity is not None:
        cli["fail_on_severity"] = _SEVERITY_MAP[fail_on_severity.lower()]
    if since_commit:
        cli["since_commit"] = since_commit
    if diff_base:
        cli["diff_base"] = diff_base
    if no_entropy:
        cli["use_entropy"] = False
    if no_keywords:
        cli["use_keywords"] = False
    if no_builtin_rules:
        cli["use_builtin_rules"] = False
    if custom_rules:
        cli["custom_rules_path"] = custom_rules
    if allowlist:
        cli["allowlist_path"] = allowlist
    if baseline:
        cli["baseline_path"] = baseline
    if generate_baseline:
        cli["generate_baseline_path"] = generate_baseline
    if exclude:
        cli["exclude_paths"] = list(exclude)
    if include:
        cli["include_paths"] = list(include)
    if max_workers is not None:
        cli["max_workers"] = max_workers
    if url:
        cli["clone_url"] = url
    if delete:
        cli["delete_after_scan"] = True

    cfg = merge_configs(file_config, cli)
    cfg.repo_path = repo_path

    # ── 3. Clone if URL given ──────────────────────────────────────────
    cloned_path: Path | None = None
    if cfg.clone_url:
        try:
            console.print(f"[cyan]Cloning[/cyan] {cfg.clone_url} ...")
            walker = GitWalker.clone(cfg.clone_url)
            cfg.repo_path = str(walker.repo_path)
            cloned_path = walker.repo_path
        except GitWalkerError as exc:
            console.print(f"[red]Clone failed:[/red] {exc}")
            sys.exit(2)

    # ── 4. Build detection engine ──────────────────────────────────────
    extra_rules: list[PatternRule] = []
    if cfg.custom_rules_path:
        p = Path(cfg.custom_rules_path)
        if p.suffix in (".yaml", ".yml"):
            extra_rules = load_rules_from_yaml(p)
        else:
            extra_rules = load_rules_from_toml(p)

    engine = DetectionEngine(
        use_builtin_rules=cfg.use_builtin_rules,
        custom_rules=extra_rules or None,
        use_entropy=cfg.use_entropy,
        use_keywords=cfg.use_keywords,
        entropy_threshold=cfg.entropy_threshold,
    )

    # ── 5. Build filters ──────────────────────────────────────────────
    allow = AllowList.load_from_file(cfg.allowlist_path) if cfg.allowlist_path else AllowList()
    path_filter = PathFilter(
        exclude_patterns=cfg.exclude_paths or None,
        include_patterns=cfg.include_paths or None,
    )

    # ── 6. Create scanner and run ──────────────────────────────────────
    from lickygit.core.scanner import ScanConfig as CoreScanConfig

    scan_cfg = CoreScanConfig(
        repo_path=cfg.repo_path,
        head_only=cfg.head_only,
        staged=cfg.staged,
        max_workers=cfg.max_workers,
        max_file_size=cfg.max_file_size,
        exclude_paths=cfg.exclude_paths,
        include_paths=cfg.include_paths,
        min_severity=cfg.min_severity,
        baseline_path=cfg.baseline_path,
        generate_baseline_path=cfg.generate_baseline_path,
        since_commit=cfg.since_commit,
        diff_base=cfg.diff_base,
    )

    try:
        scanner = Scanner(scan_cfg, engine=engine, allowlist=allow, path_filter=path_filter)
        result = scanner.scan()
        if cfg.generate_baseline_path:
            console.print(f"[bold green]Baseline file successfully generated at:[/bold green] {cfg.generate_baseline_path}")
    except GitWalkerError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(2)
    finally:
        # Cleanup cloned repo safely (handles Windows read-only locks)
        if cfg.delete_after_scan and cloned_path:
            safe_rmtree(cloned_path)

    # ── 7. Output results ──────────────────────────────────────────────
    _output_results(result, cfg)

    # ── 8. Exit code ───────────────────────────────────────────────────
    if cfg.fail_on_severity is not None:
        # Smart exit: only fail if findings at specified severity or above
        sys.exit(1 if result.has_findings_at_or_above(cfg.fail_on_severity) else 0)
    else:
        sys.exit(1 if result.has_findings else 0)


def _output_results(result: ScanResult, cfg: ScanConfig) -> None:
    """Route results to the appropriate formatter."""
    fmt = cfg.output_format.lower()

    if fmt == "terminal":
        from lickygit.output.terminal import TerminalFormatter
        TerminalFormatter(
            use_color=cfg.use_color, verbose=cfg.verbose, show_banner=cfg.show_banner,
        ).format(result)

    elif fmt == "json":
        from lickygit.output.json_fmt import JsonFormatter
        f = JsonFormatter()
        if cfg.output_file:
            f.write(result, cfg.output_file)
            console.print(f"[green]Written to {cfg.output_file}[/green]")
        else:
            click.echo(f.format(result))

    elif fmt == "csv":
        from lickygit.output.csv_fmt import CsvFormatter
        f = CsvFormatter()
        if cfg.output_file:
            f.write(result, cfg.output_file)
            console.print(f"[green]Written to {cfg.output_file}[/green]")
        else:
            click.echo(f.format(result))

    elif fmt == "sarif":
        from lickygit.output.sarif import SarifFormatter
        f = SarifFormatter()
        if cfg.output_file:
            f.write(result, cfg.output_file)
            console.print(f"[green]Written to {cfg.output_file}[/green]")
        else:
            click.echo(f.format(result))

    elif fmt == "html":
        from lickygit.output.html_report import HtmlReportFormatter
        f = HtmlReportFormatter()
        out = cfg.output_file or "lickygit-report.html"
        f.write(result, out)
        console.print(f"[green]HTML report written to {out}[/green]")

    elif fmt == "gitlab":
        from lickygit.output.gitlab_fmt import GitlabCodeQualityFormatter
        f = GitlabCodeQualityFormatter()
        out = cfg.output_file or "gl-code-quality-report.json"
        f.write(result, out)
        console.print(f"[green]GitLab Code Quality report written to {out}[/green]")


# ====================================================================== #
# config commands
# ====================================================================== #

@main.group()
def config() -> None:
    """Manage lickyGit configuration."""


@config.command("check")
@click.option("--config", "-c", "config_path", default=None, type=click.Path(exists=True), help="Config file path.")
def config_check(config_path: str | None) -> None:
    """Validate the configuration file and report warnings."""
    from lickygit.config import _find_config_file, _load_toml

    if config_path:
        p = Path(config_path)
    else:
        p = _find_config_file()

    if p is None or not p.is_file():
        console.print("[yellow]No .lickygit.toml found.[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]Checking[/cyan] {p}")
    try:
        data = _load_toml(p)
    except Exception as exc:
        console.print(f"[red]Error parsing TOML:[/red] {exc}")
        sys.exit(2)

    warnings = validate_config(data)
    if warnings:
        for w in warnings:
            console.print(f"  [yellow]Warning:[/yellow] {w}")
        console.print(f"\n[yellow]{len(warnings)} warning(s) found.[/yellow]")
        sys.exit(1)
    else:
        console.print("[bold green]Configuration is valid![/bold green]")


@config.command("show")
@click.option("--config", "-c", "config_path", default=None, type=click.Path(exists=True), help="Config file path.")
def config_show(config_path: str | None) -> None:
    """Show the effective (merged) configuration."""
    try:
        cfg = load_config(config_path)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(2)

    from dataclasses import fields
    console.print("[bold]Effective Configuration[/bold]\n")
    for f in fields(cfg):
        val = getattr(cfg, f.name)
        if isinstance(val, Severity):
            val = val.value
        console.print(f"  [cyan]{f.name}[/cyan] = {val}")


# ====================================================================== #
# hook commands
# ====================================================================== #

@main.group()
def hook() -> None:
    """Manage Git pre-commit hooks."""


@hook.command("install")
@click.option("--severity", default="high",
              type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
              help="Minimum severity to block commits (default: high).")
def hook_install(severity: str) -> None:
    """Install a pre-commit hook that blocks secrets."""
    hooks_dir = Path(".git/hooks")
    if not hooks_dir.exists():
        console.print("[red]Error:[/red] Not inside a Git repository (no .git/hooks).")
        sys.exit(2)

    hook_path = hooks_dir / "pre-commit"
    script = f"""#!/usr/bin/env sh
# lickyGit pre-commit hook — auto-generated
# Scans staged changes for secrets before committing.
lickygit scan --staged --severity {severity} --no-banner
"""
    hook_path.write_text(script, encoding="utf-8")
    hook_path.chmod(0o755)
    console.print(f"[green]Pre-commit hook installed[/green] at {hook_path}")
    console.print(f"   Blocking commits with severity >= [bold]{severity.upper()}[/bold]")


@hook.command("uninstall")
def hook_uninstall() -> None:
    """Remove the lickyGit pre-commit hook."""
    hook_path = Path(".git/hooks/pre-commit")
    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8")
        if "lickyGit" in content or "lickygit" in content:
            hook_path.unlink()
            console.print("[green]Pre-commit hook removed.[/green]")
        else:
            console.print("[yellow]Warning:[/yellow] pre-commit hook exists but was not installed by lickyGit.")
    else:
        console.print("[dim]No pre-commit hook found.[/dim]")


if __name__ == "__main__":
    main()
