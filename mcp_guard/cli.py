"""CLI interface for MCP Guard."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .formatters import to_json, to_rich, to_sarif
from .parser import MCPParser
from .scanner import Scanner


@click.group()
@click.version_option(version=__version__)
def main():
    """MCP Guard - Security scanner for MCP servers."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["cli", "json", "sarif"]),
    default="cli",
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file (default: stdout)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Exit with error if findings at or above this level",
)
def scan(
    path: str,
    output_format: str,
    output: str | None,
    fail_on: str | None,
):
    """Scan an MCP server for security risks.

    PATH can be a directory containing mcp.json or the config file itself.
    """
    console = Console()

    try:
        manifest = MCPParser.from_file(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON - {e}[/red]")
        sys.exit(1)

    scanner = Scanner()
    result = scanner.scan(manifest)

    # Format output
    if output_format == "json":
        output_str = to_json(result)
    elif output_format == "sarif":
        output_str = json.dumps(to_sarif(result), indent=2)
    else:
        to_rich(result)
        output_str = None

    # Write or print output
    if output_str is not None:
        if output:
            Path(output).write_text(output_str, encoding="utf-8")
            console.print(f"[green]Output written to {output}[/green]")
        else:
            click.echo(output_str)

    # Exit code based on fail-on threshold
    if fail_on:
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = levels[fail_on]
        max_level = max(
            (levels.get(f.level.value.lower(), 0) for f in result.findings),
            default=0,
        )
        if max_level >= threshold:
            sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
def info(path: str):
    """Show MCP server info without scanning."""
    console = Console()

    try:
        manifest = MCPParser.from_file(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    console.print(f"[bold]Server:[/bold] {manifest.name} v{manifest.version}")
    console.print(f"[bold]Description:[/bold] {manifest.description}")
    console.print(f"[bold]Capabilities:[/bold] {len(manifest.capabilities)}")

    for cap in manifest.capabilities:
        auth_status = "🔒" if cap.has_auth else "🔓"
        write_status = "✏️" if cap.is_write else ""
        destructive_status = "💥" if cap.is_destructive else ""
        console.print(
            f"  {auth_status} [{cap.type.value}] {cap.name} "
            f"{write_status} {destructive_status}"
        )
        if cap.description:
            console.print(f"    {cap.description[:80]}")


if __name__ == "__main__":
    main()
