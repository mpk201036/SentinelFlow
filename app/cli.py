"""SentinelFlow command line interface.

Stage 1 provides the commands needed to verify an installation:

    sentinelflow version
    sentinelflow config
    sentinelflow doctor

Later stages add ``init-db``, ``import``, ``demo``, ``report`` and ``serve``.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from app import __version__
from app.core.config import AIProvider, get_settings
from app.core.logging import configure_logging, get_logger

app = typer.Typer(
    name="sentinelflow",
    help="SentinelFlow — AI-Assisted Security Alert Triage System.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
logger = get_logger(__name__)

_OK = "[green]OK[/green]"
_WARN = "[yellow]WARN[/yellow]"
_FAIL = "[red]FAIL[/red]"


@app.command()
def version() -> None:
    """Print the SentinelFlow version."""
    console.print(f"SentinelFlow [bold]{__version__}[/bold]")


@app.command()
def config() -> None:
    """Show the effective configuration (secrets excluded)."""
    settings = get_settings()
    table = Table(title="SentinelFlow configuration", header_style="bold", title_style="bold")
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value")
    for key, value in settings.summary().items():
        table.add_row(key, str(value))
    console.print(table)
    if not settings.ai_active:
        console.print(
            "\n[dim]AI is disabled. The deterministic pipeline is fully functional "
            "without it; no model will be contacted.[/dim]"
        )


@app.command()
def doctor() -> None:
    """Check that the environment is correctly set up."""
    configure_logging()
    settings = get_settings()

    table = Table(title="SentinelFlow environment check", header_style="bold", title_style="bold")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")

    failures = 0

    # --- Python version -------------------------------------------------
    py_ok = sys.version_info >= (3, 12)
    failures += 0 if py_ok else 1
    table.add_row(
        "Python >= 3.12",
        _OK if py_ok else _FAIL,
        f"{platform.python_version()} ({sys.executable})",
    )

    # --- Dependencies ---------------------------------------------------
    for module_name, label in (
        ("fastapi", "FastAPI"),
        ("pydantic", "Pydantic"),
        ("sqlalchemy", "SQLAlchemy"),
        ("jinja2", "Jinja2"),
        ("yaml", "PyYAML"),
        ("httpx", "httpx"),
    ):
        try:
            module = __import__(module_name)
            detail = getattr(module, "__version__", "installed")
            table.add_row(label, _OK, str(detail))
        except ImportError:
            failures += 1
            table.add_row(label, _FAIL, "not installed")

    # --- Project layout -------------------------------------------------
    for directory in ("rules", "data/samples", "data/mitre", "dashboard/templates", "tests"):
        exists = (settings.project_root / directory).is_dir()
        failures += 0 if exists else 1
        table.add_row(
            f"dir: {directory}", _OK if exists else _FAIL, "present" if exists else "missing"
        )

    # --- Database location writable -------------------------------------
    db_detail, db_status = _check_database_path(settings.database_url)
    if db_status is _FAIL:
        failures += 1
    table.add_row("database path", db_status, db_detail)

    # --- Optional AI ----------------------------------------------------
    if not settings.ai_active:
        table.add_row(
            "AI provider",
            _OK,
            f"disabled (provider={settings.ai_provider.value}) - not required",
        )
    elif settings.ai_provider is AIProvider.OLLAMA:
        table.add_row(*_check_ollama(settings.ollama_base_url))

    console.print(table)

    if failures:
        console.print(f"\n[red]{failures} check(s) failed.[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


def _check_database_path(database_url: str) -> tuple[str, str]:
    """Verify the SQLite parent directory exists and is writable."""
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return (f"non-SQLite URL configured: {database_url.split('://')[0]}://...", _OK)
    raw = database_url[len(prefix) :]
    if raw == ":memory:":
        return ("in-memory database", _OK)
    parent = Path("/" + raw.lstrip("/")).parent if raw.startswith("/") else Path(raw).parent
    if not parent.exists():
        return (f"{parent} does not exist", _FAIL)
    if not os.access(parent, os.W_OK):
        return (f"{parent} is not writable", _FAIL)
    return (f"{parent} is writable", _OK)


def _check_ollama(base_url: str) -> tuple[str, str, str]:
    """Probe a local Ollama instance. Never fatal — AI is optional."""
    try:
        import httpx

        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=3.0)
        response.raise_for_status()
        models = [entry.get("name", "?") for entry in response.json().get("models", [])]
        detail = ", ".join(models[:5]) if models else "reachable, no models pulled"
        return ("AI provider", _OK, f"ollama at {base_url}: {detail}")
    except Exception as exc:  # any failure simply means "no AI available"
        return (
            "AI provider",
            _WARN,
            f"ollama unreachable at {base_url} ({type(exc).__name__}). "
            "SentinelFlow continues without AI.",
        )


if __name__ == "__main__":  # pragma: no cover
    app()
