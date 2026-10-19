import argparse
import sys
import time
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from scapy.all import get_if_list

from sniffer.runner import PacketCaptureRunner
from sniffer.database import AlertDatabase


console = Console()


def list_network_interfaces():
    table = Table(title="Available Network Interfaces", show_header=True, header_style="bold cyan")
    table.add_column("Index", style="dim", width=6)
    table.add_column("Interface Name / Identifier", style="bold green")

    try:
        ifaces = get_if_list()
        for i, iface in enumerate(ifaces, 1):
            table.add_row(str(i), iface)
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to enumerate interfaces:[/bold red] {e}")


def display_saved_alerts(db_path: str = "alerts.db", limit: int = 50):
    db = AlertDatabase(db_path=db_path)
    alerts = db.get_recent_alerts(limit=limit)

    if not alerts:
        console.print(f"[yellow]No security alerts found in '{db_path}'.[/yellow]")
        return

    table = Table(title=f"Forensic Security Alerts ({len(alerts)} most recent)", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=5)
    table.add_column("Timestamp (UTC)", width=24)
    table.add_column("Attack Type", style="bold red", width=16)
    table.add_column("Source IP", style="yellow", width=16)
    table.add_column("Source MAC", style="dim", width=18)
    table.add_column("Target IP:Port", width=18)
    table.add_column("Description", style="white")

    for a in alerts:
        target = f"{a['target_ip'] or '-'}:{a['target_port'] or '-'}"
        table.add_row(
            str(a["id"]),
            a["timestamp"][:19].replace("T", " "),
            a["attack_type"],
            a["source_ip"],
            a.get("source_mac") or "-",
            target,
            a["description"],
        )

    console.print(table)


def build_dashboard(stats: Dict[str, Any], recent_alerts: List[Dict[str, Any]], mode_info: str) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=8),
        Layout(name="alerts", ratio=1),
    )

    # 1. Header
    title_text = Text(f"Packet Sniffer & Anomaly Detector | Mode: {mode_info}", style="bold cyan")
    layout["header"].update(Panel(title_text, style="blue"))

    # 2. Stats & Protocol Distribution
    proto = stats.get("protocol_counts", {})
    total_processed = max(stats.get("packets_processed", 0), 1)

    stats_table = Table(show_header=True, header_style="bold green", expand=True)
    stats_table.add_column("Captured", justify="center")
    stats_table.add_column("Processed", justify="center")
    stats_table.add_column("Dropped", justify="center", style="bold red" if stats.get("packets_dropped", 0) > 0 else "green")
    stats_table.add_column("Throughput", justify="center", style="bold yellow")
    stats_table.add_column("TCP", justify="center")
    stats_table.add_column("UDP", justify="center")
    stats_table.add_column("ICMP", justify="center")
    stats_table.add_column("ARP", justify="center")
    stats_table.add_column("Alerts", justify="center", style="bold red" if stats.get("alerts_triggered", 0) > 0 else "white")

    stats_table.add_row(
        str(stats.get("packets_captured", 0)),
        str(stats.get("packets_processed", 0)),
        str(stats.get("packets_dropped", 0)),
        f"{stats.get('current_pps', 0.0):.1f} pkts/s",
        f"{proto.get('TCP', 0)} ({proto.get('TCP', 0)/total_processed:.1%})",
        f"{proto.get('UDP', 0)} ({proto.get('UDP', 0)/total_processed:.1%})",
        f"{proto.get('ICMP', 0)} ({proto.get('ICMP', 0)/total_processed:.1%})",
        f"{proto.get('ARP', 0)} ({proto.get('ARP', 0)/total_processed:.1%})",
        str(stats.get("alerts_triggered", 0)),
    )

    layout["stats"].update(Panel(stats_table, title="Pipeline Telemetry & Protocols", border_style="green"))

    # 3. Live Alerts Table
    alerts_table = Table(show_header=True, header_style="bold red", expand=True)
    alerts_table.add_column("Timestamp", width=12)
    alerts_table.add_column("Attack Type", style="bold red", width=16)
    alerts_table.add_column("Source IP", style="yellow", width=16)
    alerts_table.add_column("Target IP:Port", width=18)
    alerts_table.add_column("Description", style="white")

    for a in recent_alerts[-6:]:
        target = f"{a.get('target_ip') or '-'}:{a.get('target_port') or '-'}"
        ts = a.get("timestamp", time.strftime("%H:%M:%S"))
        if "T" in ts:
            ts = ts.split("T")[1][:8]
        alerts_table.add_row(
            ts,
            a.get("attack_type", "UNKNOWN"),
            a.get("source_ip", "-"),
            target,
            a.get("description", "-"),
        )

    layout["alerts"].update(Panel(alerts_table, title=f"Security Anomalies (Showing latest {min(len(recent_alerts), 6)})", border_style="red"))
    return layout


def main():
    parser = argparse.ArgumentParser(description="Real-Time Network Packet Sniffer & Anomaly Detector")
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    parser.add_argument("-p", "--pcap", help="Offline PCAP file to replay")
    parser.add_argument("-f", "--filter", help="BPF packet filter (e.g. 'tcp or arp')")
    parser.add_argument("-c", "--count", type=int, help="Maximum number of packets to capture")
    parser.add_argument("--db", default="alerts.db", help="Path to SQLite alerts database (default: alerts.db)")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--view-alerts", action="store_true", help="Display stored alerts from forensic DB and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        list_network_interfaces()
        return

    if args.view_alerts:
        display_saved_alerts(db_path=args.db)
        return

    if not args.interface and not args.pcap:
        console.print("[bold yellow]No capture source specified.[/bold yellow]")
        console.print("Run with [cyan]--interface <name>[/cyan] for live traffic or [cyan]--pcap <file.pcap>[/cyan] for replay.")
        console.print("Use [cyan]--list-interfaces[/cyan] to inspect local adapters.")
        return

    mode_info = f"PCAP Replay ({args.pcap})" if args.pcap else f"Live Adapter ({args.interface})"
    recent_alerts: List[Dict[str, Any]] = []

    def on_alert_received(alert: Dict[str, Any]):
        recent_alerts.append(alert)

    runner = PacketCaptureRunner(
        interface=args.interface,
        pcap_file=args.pcap,
        bpf_filter=args.filter,
        packet_limit=args.count,
        db_path=args.db,
        on_alert=on_alert_received,
    )

    console.print(f"[bold green]Starting sniffer on {mode_info}...[/bold green] (Press Ctrl+C to stop)\n")

    runner.start()

    try:
        with Live(build_dashboard(runner.stats, recent_alerts, mode_info), refresh_per_second=4, console=console) as live:
            while not runner._stop_event.is_set():
                time.sleep(0.25)
                live.update(build_dashboard(runner.stats, recent_alerts, mode_info))
            # Final render
            live.update(build_dashboard(runner.stats, recent_alerts, mode_info))
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown requested by user.[/yellow]")
    finally:
        runner.stop()
        console.print(f"[bold green]Session completed.[/bold green] Total processed: {runner.stats['packets_processed']} packets.")


if __name__ == "__main__":
    main()
