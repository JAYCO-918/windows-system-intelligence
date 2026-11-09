"""Command-line interface for Windows System Intelligence (WSI).

Provides subcommands:
- `inventory`: Run read-only collectors and display results
- `diagnose`: Run collectors and diagnostic analyzers
- `list`: Show available collectors and analyzers

ALL operations are strictly read-only and non-destructive.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from wsi import __version__
from wsi.analyzers import get_all_analyzers, get_analyzer
from wsi.collectors import get_all_collectors, get_collector
from wsi.core.base import AnalysisResult, CollectorResult
from wsi.core.formatting import format_json, format_table, format_summary
from wsi.core.html_report import generate_html_report


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_collector_result(res: CollectorResult) -> None:
    print(f"\n{'='*70}")
    print(f"Collector: {res.collector_name} ({res.duration_seconds:.2f}s)")
    print(f"{'='*70}")

    if res.errors:
        print("  Errors encountered:")
        for err in res.errors:
            print(f"    - {err}")

    if not res.data:
        print("  (No data collected)")
        return

    if res.collector_name == "installed_apps":
        headers = ["Name", "Version", "Publisher", "Source"]
        rows = []
        for app in res.data[:50]:
            rows.append([
                app.get("name") or "",
                app.get("version") or "",
                app.get("publisher") or "",
                app.get("source") or "",
            ])
        print(format_table(headers, rows))
        if len(res.data) > 50:
            print(f"\n  ... and {len(res.data) - 50} more (use --format json for full list)")

    elif res.collector_name == "services":
        headers = ["Type", "Name", "Display Name", "State", "Start Mode"]
        rows = []
        sorted_data = sorted(
            res.data, key=lambda x: (not x.get("is_running"), x.get("name", ""))
        )
        for svc in sorted_data[:50]:
            rows.append([
                svc.get("category") or "",
                svc.get("name") or "",
                svc.get("display_name") or "",
                svc.get("state") or "",
                svc.get("start_mode") or "",
            ])
        print(format_table(headers, rows))
        if len(res.data) > 50:
            print(f"\n  ... and {len(res.data) - 50} more")

    elif res.collector_name == "startup":
        headers = ["Name", "Source", "Scope", "Command"]
        rows = []
        for item in res.data:
            rows.append([
                item.get("name") or "",
                item.get("source") or "",
                item.get("scope") or "",
                item.get("command") or "",
            ])
        print(format_table(headers, rows))

    elif res.collector_name == "storage":
        data = res.data[0] if res.data else {}
        print(f"\nTotal Capacity: {data.get('total_capacity_gb', 0)} GB")
        print(f"Total Free:     {data.get('total_free_gb', 0)} GB")
        print(f"Total Used:     {data.get('total_used_gb', 0)} GB\n")

        headers = ["Drive", "Label", "File System", "Size (GB)", "Free (GB)", "Used %"]
        rows = []
        for disk in data.get("logical_disks", []):
            rows.append([
                disk.get("drive") or "",
                disk.get("label") or "",
                disk.get("file_system") or "",
                str(disk.get("size_gb") or ""),
                str(disk.get("free_gb") or ""),
                f"{disk.get('usage_percent')}%" if disk.get("usage_percent") else "",
            ])
        print(format_table(headers, rows))

    elif res.collector_name == "system_info":
        data = res.data[0] if res.data else {}
        os_info = data.get("os", {})
        hw_info = data.get("hardware", {})
        ident = data.get("identity", {})

        summary_items = {
            "OS": os_info.get("caption"),
            "Version": f"{os_info.get('version')} (Build {os_info.get('build_number')})",
            "Architecture": os_info.get("architecture"),
            "Computer Name": ident.get("computer_name"),
            "Current User": ident.get("username"),
            "Processor": hw_info.get("cpu", {}).get("name"),
            "Total RAM": f"{hw_info.get('memory_total_gb')} GB" if hw_info.get("memory_total_gb") else None,
        }
        print(format_summary("System Summary", {k: v for k, v in summary_items.items() if v}))

    elif res.collector_name == "execution_history":
        headers = ["Executable", "Source", "Last Seen", "Run Count"]
        rows = []
        for item in res.data[:30]:
            rows.append([
                item.get("executable") or "",
                item.get("source") or "",
                item.get("last_seen") or "",
                str(item.get("run_count") or ""),
            ])
        print(format_table(headers, rows))
        if len(res.data) > 30:
            print(f"\n  ... and {len(res.data) - 30} more")

    elif res.collector_name == "environment":
        data = res.data[0] if res.data else {}
        runtimes = data.get("detected_runtimes", [])
        if runtimes:
            print("\nDetected Development Runtimes:")
            headers = ["Runtime", "Version", "Path"]
            rows = [[r.get("name", ""), r.get("version", ""), r.get("path", "")] for r in runtimes]
            print(format_table(headers, rows))

        path_info = data.get("path_analysis", {})
        print(f"\nPATH Analysis:")
        print(f"  Total entries:       {path_info.get('total_entries', 0)}")
        print(f"  Valid directories:   {path_info.get('valid_directories', 0)}")
        print(f"  Missing directories: {path_info.get('missing_directories', 0)}")
        print(f"  Duplicates:          {path_info.get('duplicates', 0)}")

    elif res.collector_name == "event_logs":
        headers = ["Time", "Category", "Event ID", "Provider", "Summary"]
        rows = []
        for ev in res.data[:25]:
            rows.append([
                ev.get("time_created") or "",
                ev.get("category") or "",
                str(ev.get("id") or ""),
                ev.get("provider") or "",
                ev.get("message") or "",
            ])
        print(format_table(headers, rows))
        if len(res.data) > 25:
            print(f"\n  ... and {len(res.data) - 25} more")

    elif res.collector_name == "network_surface":
        data = res.data[0] if res.data else {}
        print("\nWindows Firewall Profiles:")
        for prof in data.get("firewall_profiles", []):
            status = "Enabled" if prof.get("enabled") else "DISABLED"
            print(f"  {prof.get('name', '').ljust(12)}: {status} (Inbound: {prof.get('inbound_action')}, Outbound: {prof.get('outbound_action')})")

        print(f"\nActive Listening TCP Ports ({len(data.get('listening_tcp', []))} endpoints):")
        headers = ["Port", "Address", "PID"]
        rows = [[str(p.get("port")), p.get("address") or "", str(p.get("pid"))] for p in data.get("listening_tcp", [])[:30]]
        print(format_table(headers, rows))
        if len(data.get("listening_tcp", [])) > 30:
            print(f"  ... and {len(data.get('listening_tcp', [])) - 30} more")

        shares = data.get("smb_shares", [])
        if shares:
            print("\nConfigured SMB File Shares:")
            headers = ["Name", "Path", "Special (Admin)"]
            rows = [[s.get("name", ""), s.get("path", ""), str(s.get("special"))] for s in shares]
            print(format_table(headers, rows))

    else:
        print(f"  Collected {len(res.data)} items.")


def _print_analysis_result(res: AnalysisResult) -> None:
    print(f"\n{'='*70}")
    print(f"Diagnostic: {res.analyzer_name} ({res.duration_seconds:.2f}s)")
    print(f"{'='*70}")
    print(f"Summary: {res.summary}\n")

    if not res.findings:
        print("  No issues detected.")
        return

    sev_icons = {"critical": "[!]", "warning": "[?]", "info": "[i]"}
    for f in res.findings:
        icon = sev_icons.get(f.severity, "[-]")
        print(f"  {icon} [{f.severity.upper()}] {f.title}")
        if f.description:
            print(f"      {f.description}")
        if f.recommendation:
            print(f"      Recommendation: {f.recommendation}")
        print()


def handle_inventory(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)

    if args.collector:
        collector = get_collector(args.collector)
        if not collector:
            print(f"Unknown collector: {args.collector}", file=sys.stderr)
            return 1
        collectors = [collector]
    else:
        collectors = get_all_collectors()

    results: dict[str, CollectorResult] = {}
    for col in collectors:
        if not args.json:
            print(f"Running {col.name} collector...")
        res = col.safe_collect()
        results[col.name] = res

    if args.json:
        output_data = {
            name: res.to_dict() for name, res in results.items()
        }
        json_str = format_json(output_data)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Results written to {args.output}")
        else:
            print(json_str)
    else:
        for res in results.values():
            _print_collector_result(res)

    return 0


def handle_diagnose(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)

    collectors = get_all_collectors()
    collector_results: dict[str, CollectorResult] = {}

    if not args.json:
        print("Collecting system intelligence (read-only)...")
    for col in collectors:
        collector_results[col.name] = col.safe_collect()

    if args.analyzer:
        analyzer = get_analyzer(args.analyzer)
        if not analyzer:
            print(f"Unknown analyzer: {args.analyzer}", file=sys.stderr)
            return 1
        analyzers = [analyzer]
    else:
        analyzers = get_all_analyzers()

    analysis_results: dict[str, AnalysisResult] = {}
    if not args.json:
        print("Running diagnostic analyzers...")
    for an in analyzers:
        analysis_results[an.name] = an.safe_analyze(collector_results)

    # HTML export
    if args.html:
        html_content = generate_html_report(collector_results, analysis_results)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"Interactive HTML report generated at {args.html}")

    if args.json:
        output_data = {
            "collectors": {name: r.to_dict() for name, r in collector_results.items()},
            "diagnostics": {name: r.to_dict() for name, r in analysis_results.items()},
        }
        json_str = format_json(output_data)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Results written to {args.output}")
        else:
            print(json_str)
    elif not args.html:
        for res in analysis_results.values():
            _print_analysis_result(res)

    return 0


def handle_list(args: argparse.Namespace) -> int:
    print("Available Read-Only Collectors:")
    for col in get_all_collectors():
        print(f"  - {col.name.ljust(20)} : {col.description}")

    print("\nAvailable Diagnostic Analyzers:")
    for an in get_all_analyzers():
        print(f"  - {an.name.ljust(20)} : {an.description}")

    return 0


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wsi",
        description=(
            "Windows System Intelligence (WSI) — Read-only diagnostic toolkit.\n"
            "Guaranteed zero host system modification."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"WSI {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # inventory
    inv_parser = subparsers.add_parser("inventory", help="Run read-only system data collectors")
    inv_parser.add_argument(
        "-c", "--collector",
        choices=[
            "installed_apps", "services", "startup",
            "system_info", "storage", "execution_history", "environment", "event_logs", "network_surface",
        ],
        help="Run only a specific collector",
    )
    inv_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    inv_parser.add_argument("-o", "--output", help="Write JSON output to a file")

    # diagnose
    diag_parser = subparsers.add_parser("diagnose", help="Run diagnostic health and conflict analyzers")
    diag_parser.add_argument(
        "-a", "--analyzer",
        choices=["health", "software", "startup_impact", "driver_security", "event_health"],
        help="Run only a specific analyzer",
    )
    diag_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    diag_parser.add_argument("-o", "--output", help="Write JSON output to a file")
    diag_parser.add_argument("--html", help="Generate an interactive single-file HTML report at the specified path")

    # list
    subparsers.add_parser("list", help="List available collectors and analyzers")

    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "inventory": handle_inventory,
        "diagnose": handle_diagnose,
        "list": handle_list,
    }

    handler = handlers.get(args.subcommand)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
