"""
Chain-Mind Auditor: Unified Quickstart & Automatic Shortcut Launcher.

This shortcut launcher provides an intuitive interface for new users to explore
and launch the 3 core modes of Chain-Mind Auditor, as well as automatic functions
for direct execution without user prompts.

3 Modes of Operation:
  1. Web Operations Center (FastAPI Dashboard & Interactive REST API)
  2. Terminal CLI Operations Menu (Interactive Smart Contract Auditing & Mempool Analyzer)
  3. Automated Test Suite (51+ Cross-Layer Verification Tests)
"""

import sys
import os
import argparse
from pathlib import Path

# Automatically ensure environment dependencies exist or auto-switch to local .venv
try:
    import httpx
except ModuleNotFoundError:
    venv_python = (
        Path(__file__).resolve().parent
        / ".venv"
        / ("Scripts" if sys.platform == "win32" else "bin")
        / ("python.exe" if sys.platform == "win32" else "python")
    )
    if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
        import subprocess
        result = subprocess.run([str(venv_python), str(Path(__file__).resolve())] + sys.argv[1:])
        sys.exit(result.returncode)

# Try importing rich for enhanced UI, fallback to standard print if absent
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    console = Console(safe_box=True)
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

# Import core runners from main
from main import run_web_server, interactive_menu


def auto_run_web(host: str = "127.0.0.1", port: int = 5000):
    """
    Automatic function caller: Directly launches the Web Operations Center
    without requiring any user prompt or manual intervention.
    """
    print(f"\n[+] Auto-launching Web Operations Center on http://{host}:{port} ...\n")
    run_web_server(host=host, port=port)


def auto_run_menu():
    """
    Automatic function caller: Directly launches the interactive terminal CLI menu.
    """
    print("\n[+] Auto-launching Interactive CLI Operations Menu...\n")
    interactive_menu()


def auto_run_tests():
    """
    Automatic function caller: Directly executes the automated pytest test suite.
    """
    print("\n[+] Auto-launching Automated Test Suite (pytest)...\n")
    import pytest
    return pytest.main(["-v", "tests"])


def auto_run(mode: str = "web", host: str = "127.0.0.1", port: int = 5000):
    """
    Master automatic runner function that executes any specified run mode
    programmatically without user intervention.
    """
    mode_normalized = mode.lower().strip()
    if mode_normalized in ("1", "web", "dashboard"):
        return auto_run_web(host=host, port=port)
    elif mode_normalized in ("2", "menu", "cli"):
        return auto_run_menu()
    elif mode_normalized in ("3", "test", "tests", "run-tests"):
        return auto_run_tests()
    else:
        raise ValueError(f"Unknown mode '{mode}'. Choose from: 'web', 'menu', 'tests'.")


def show_interactive_quickstart():
    """
    Interactive visual guide and shortcut menu designed to help new users
    understand the 3 run modes and easily navigate between them.
    """
    if HAS_RICH:
        console.clear()
        console.print(Panel(
            "[bold cyan]CHAIN-MIND AUDITOR — QUICKSTART & SHORTCUT LAUNCHER[/bold cyan]\n"
            "[dim]Welcome! Select one of the 3 core modes below to run the application.[/dim]",
            title="[bold gold1]Quickstart Navigator[/bold gold1]",
            border_style="cyan"
        ))

        table = Table(title="Available Execution Modes", border_style="dim", header_style="bold magenta")
        table.add_column("Option", style="bold yellow", width=8, justify="center")
        table.add_column("Mode Name", style="bold green", width=26)
        table.add_column("Description & Features", style="white")

        table.add_row(
            "1",
            "[Web] Web Operations Center",
            "Full browser UI dashboard, live analytics, contract audit submission, & OpenAPI interactive docs (http://127.0.0.1:5000)"
        )
        table.add_row(
            "2",
            "[CLI] Terminal CLI Menu",
            "Interactive command-line workspace for single contract auditing, directory batch audits, & real-time mempool monitoring"
        )
        table.add_row(
            "3",
            "[Test] Automated Test Suite",
            "Runs the complete 51+ unit/integration test suite using pytest across ingestion, heuristics, guardrails, & web APIs"
        )

        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select a mode to run[/bold yellow]",
            choices=["1", "2", "3", "q"],
            default="1"
        )

        if choice == "1":
            auto_run_web()
        elif choice == "2":
            auto_run_menu()
        elif choice == "3":
            auto_run_tests()
        elif choice.lower() == "q":
            console.print("[dim]Exiting Quickstart Launcher.[/dim]")
            sys.exit(0)
    else:
        print("\n==========================================================")
        print("  CHAIN-MIND AUDITOR — QUICKSTART & SHORTCUT LAUNCHER")
        print("==========================================================\n")
        print("1. [Web] Web Operations Center (Browser UI & API server at http://127.0.0.1:5000)")
        print("2. [CLI] Terminal CLI Menu (Interactive contract auditing & mempool analysis)")
        print("3. [Test] Automated Test Suite (Executes 51+ pytest test cases)\n")

        choice = input("Select a mode to run (1-3) [default: 1]: ").strip() or "1"
        if choice == "1":
            auto_run_web()
        elif choice == "2":
            auto_run_menu()
        elif choice == "3":
            auto_run_tests()
        else:
            print("Exiting.")
            sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Chain-Mind Auditor Quickstart & Automatic Shortcut Launcher"
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Directly auto-run the Web Operations Center without user prompts"
    )
    parser.add_argument(
        "--mode", choices=["web", "menu", "tests"], default=None,
        help="Specify which mode to auto-run directly (web, menu, tests)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host address for web mode (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Port number for web mode (default: 5000)"
    )
    return parser.parse_args()


# Direct function caller entry point when executed directly
if __name__ == "__main__":
    args = parse_args()

    # If --auto or --mode is provided, execute without user prompts
    if args.auto:
        auto_run(mode="web", host=args.host, port=args.port)
    elif args.mode:
        auto_run(mode=args.mode, host=args.host, port=args.port)
    else:
        # Otherwise launch the interactive user navigator
        show_interactive_quickstart()
