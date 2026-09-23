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
from app.database.init_db import database_status, initialize_database
from app.database.session import get_engine, session_scope
from app.ingestion import IngestionService, generate_dataset, group_by_adapter, list_adapters
from app.ingestion.service import IngestionOutcome
from app.models.ingestion import IngestionReport

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


@app.command("init-db")
def init_db(
    force: bool = typer.Option(
        False, "--force", help="Drop every existing table first. DESTROYS ALL STORED DATA."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Create the database schema, or bring an existing one up to date."""
    configure_logging()
    settings = get_settings()

    if force and not yes:
        console.print(
            "[bold red]--force drops every table.[/bold red] All stored events, alerts "
            "and analyst notes will be permanently lost."
        )
        console.print(f"Database: [cyan]{settings.database_url}[/cyan]")
        if not typer.confirm("Continue?"):
            console.print("Aborted. Nothing was changed.")
            raise typer.Exit(code=1)

    report = initialize_database(get_engine(settings), drop_existing=force)
    console.print(f"[green]Database ready[/green] - {report.describe()}")
    console.print(f"[dim]{report.database_url}[/dim]")


@app.command("db-info")
def db_info() -> None:
    """Show schema version, table sizes and integrity settings."""
    settings = get_settings()
    status = database_status(get_engine(settings))

    if not status["initialised"]:
        console.print("[yellow]Database is not initialised.[/yellow] Run: sentinelflow init-db")
        raise typer.Exit(code=1)

    summary = Table(title="SentinelFlow database", header_style="bold", title_style="bold")
    summary.add_column("Property", style="cyan", no_wrap=True)
    summary.add_column("Value")
    size = status["size_bytes"]
    summary.add_row("location", status["path"] or status["database_url"])
    summary.add_row("size", f"{size / 1024:.1f} KiB" if size else "in-memory")
    summary.add_row(
        "schema version",
        f"{status['schema_version']} of {status['expected_version']}"
        + ("" if status["up_to_date"] else "  [yellow](migration pending)[/yellow]"),
    )
    summary.add_row(
        "foreign keys", "enforced" if status["foreign_keys_enforced"] else "[red]NOT enforced[/red]"
    )
    summary.add_row("tables", str(status["table_count"]))
    console.print(summary)

    rows = Table(title="Row counts", header_style="bold", title_style="bold")
    rows.add_column("Table", style="cyan", no_wrap=True)
    rows.add_column("Rows", justify="right")
    for name, count in status["row_counts"].items():
        rows.add_row(name, str(count))
    console.print(rows)


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

    # --- Schema ---------------------------------------------------------
    try:
        status = database_status(get_engine(settings))
        if not status["initialised"]:
            table.add_row("database schema", _WARN, "not initialised - run: sentinelflow init-db")
        elif not status["up_to_date"]:
            failures += 1
            table.add_row(
                "database schema",
                _FAIL,
                f"version {status['schema_version']}, expected {status['expected_version']}",
            )
        else:
            table.add_row(
                "database schema",
                _OK,
                f"version {status['schema_version']}, {status['table_count']} tables, "
                f"foreign keys {'enforced' if status['foreign_keys_enforced'] else 'OFF'}",
            )
    except Exception as exc:
        failures += 1
        table.add_row("database schema", _FAIL, f"{type(exc).__name__}: {exc}")

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


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
def _print_report(report: IngestionReport) -> None:
    """Render an import result, rejections included."""
    if report.duplicate_batch:
        console.print(
            f"[yellow]Skipped[/yellow] {report.origin}: identical content already imported."
        )
        console.print("[dim]Pass --force to import it again.[/dim]")
        return

    colour = "green" if report.rejected == 0 else "yellow"
    console.print(
        f"[{colour}]{report.accepted} accepted[/{colour}], {report.rejected} rejected "
        f"via the [cyan]{report.adapter}[/cyan] adapter ({report.duration_ms} ms)"
    )

    if not report.rejections:
        return

    table = Table(title="Rejected records", header_style="bold", title_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Reason", style="yellow", no_wrap=True)
    table.add_column("Detail")
    for rejection in report.rejections[:15]:
        table.add_row(str(rejection.index), rejection.reason.value, rejection.detail[:90])
    console.print(table)
    if len(report.rejections) > 15:
        console.print(
            f"[dim]...and {len(report.rejections) - 15} more. See: sentinelflow rejections[/dim]"
        )


@app.command("import")
def import_events(
    path: Path = typer.Argument(..., help="JSON, NDJSON or CSV file to import."),
    source: str | None = typer.Option(
        None, "--source", "-s", help="Adapter name. Auto-detected when omitted."
    ),
    force: bool = typer.Option(False, "--force", help="Import again even if already seen."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Normalise and report, but store nothing."
    ),
) -> None:
    """Import security events from a file."""
    configure_logging()
    settings = get_settings()

    try:
        with session_scope(settings) as session:
            outcome = IngestionService(session, settings).ingest_file(
                path, adapter_name=source, force=force, persist=not dry_run
            )
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]{type(exc).__name__}:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if dry_run:
        console.print("[dim]Dry run - nothing was stored.[/dim]")
    _print_report(outcome.report)
    if outcome.report.rejected and not outcome.report.accepted:
        raise typer.Exit(code=1)


@app.command()
def generate(
    out: Path = typer.Option(
        Path("data/samples"), "--out", "-o", help="Directory to write sample files into."
    ),
    normal: int = typer.Option(40, "--normal", "-n", help="Number of benign background events."),
    seed: int = typer.Option(1337, "--seed", help="Seed, so output is reproducible."),
    scenario: bool = typer.Option(
        True, "--scenario/--no-scenario", help="Include the demo attack chain."
    ),
) -> None:
    """Write synthetic sample datasets, one file per source."""
    import json as _json

    records = generate_dataset(normal_count=normal, include_scenario=scenario, seed=seed)
    grouped = group_by_adapter(records)
    out.mkdir(parents=True, exist_ok=True)

    table = Table(title="Generated samples", header_style="bold", title_style="bold")
    table.add_column("File", style="cyan")
    table.add_column("Records", justify="right")
    for adapter_name, items in sorted(grouped.items()):
        destination = out / f"{adapter_name}.json"
        destination.write_text(_json.dumps(items, indent=2) + "\n", encoding="utf-8")
        table.add_row(str(destination), str(len(items)))
    console.print(table)
    console.print(
        f"[dim]All data is synthetic. Import with: sentinelflow import {out}/sysmon.json[/dim]"
    )


@app.command()
def demo(
    force: bool = typer.Option(False, "--force", help="Import again even if already seen."),
) -> None:
    """Generate the demonstration dataset and ingest it in one step."""
    configure_logging()
    settings = get_settings()
    grouped = group_by_adapter(generate_dataset())

    outcomes: list[IngestionOutcome] = []
    with session_scope(settings) as session:
        service = IngestionService(session, settings)
        for adapter_name, records in sorted(grouped.items()):
            outcomes.append(
                service.ingest_mappings(
                    records, adapter_name=adapter_name, origin=f"demo:{adapter_name}", force=force
                )
            )

    table = Table(title="Demo ingestion", header_style="bold", title_style="bold")
    table.add_column("Source", style="cyan")
    table.add_column("Accepted", justify="right")
    table.add_column("Rejected", justify="right")
    for outcome in outcomes:
        table.add_row(outcome.report.adapter, str(outcome.accepted), str(outcome.rejected))
    console.print(table)
    console.print(f"[green]{sum(o.accepted for o in outcomes)} events ingested.[/green]")


@app.command()
def adapters() -> None:
    """List the source adapters available for import."""
    table = Table(title="Source adapters", header_style="bold", title_style="bold")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Aliases", style="dim")
    table.add_column("Description")
    for adapter in list_adapters():
        table.add_row(adapter.name, ", ".join(adapter.aliases) or "-", adapter.description)
    console.print(table)


@app.command()
def rejections(
    limit: int = typer.Option(20, "--limit", "-l", help="How many to show."),
) -> None:
    """Show records that could not be normalised."""
    from app.database import repository

    settings = get_settings()
    with session_scope(settings) as session:
        records = repository.list_rejections(session, limit=limit)

    if not records:
        console.print("[green]No rejected records.[/green]")
        return

    table = Table(title="Rejected records", header_style="bold", title_style="bold")
    table.add_column("When", style="dim", no_wrap=True)
    table.add_column("Origin", style="cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Reason", style="yellow", no_wrap=True)
    table.add_column("Detail")
    for record in records:
        table.add_row(
            record.rejected_at.strftime("%Y-%m-%d %H:%M"),
            record.origin or "-",
            str(record.index),
            record.reason.value,
            record.detail[:70],
        )
    console.print(table)
