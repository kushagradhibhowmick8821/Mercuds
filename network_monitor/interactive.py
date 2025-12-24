#!/usr/bin/env python3
"""
Mercuds IDS - Unified Interactive CLI
Combines all modules: Network Monitor, Threat Intel, Actions, Dashboard
"""

import cmd
import os
import sys
import threading
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich import box

from sniffer import PacketSniffer
from analyzer import TrafficAnalyzer
from actions import ActionEngine
from threat_intel import ThreatIntelligence, ThreatIndicator
from dashboard import Dashboard

# Import GeoIP
try:
    from geoip import geoip, GeoIPLookup
except ImportError:
    geoip = None


class MercudsCLI(cmd.Cmd):
    """
    Unified Interactive CLI for Mercuds IDS
    All modules accessible from one interface
    """
    
    intro = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║            🛡️  MERCUDS - Intrusion Detection System  🛡️               ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  QUICK START:                                                        ║
║    1. start          - Begin packet capture                          ║
║    2. watch          - View live traffic (Ctrl+C to return)          ║
║    3. alerts         - Check detected threats                        ║
║    4. block <ip>     - Block malicious IP                            ║
║                                                                      ║
║  Type 'menu' for all commands or 'help <cmd>' for details            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    prompt = "\n\033[1;36mmercuds>\033[0m "
    
    def __init__(self, interface: str = None):
        super().__init__()
        self.console = Console()
        self.interface = interface
        
        # === Initialize All Modules ===
        self.sniffer = PacketSniffer(interface=interface)
        self.analyzer = TrafficAnalyzer()
        self.actions = ActionEngine()
        self.threat_intel = ThreatIntelligence()
        self.dashboard = Dashboard()
        
        # Wire threat intel into analyzer
        self._setup_threat_intel_integration()
        
        # State
        self.is_capturing = False
        self.captured_packets = []
        self.max_stored_packets = 1000
        self._dashboard_thread = None
    
    def _setup_threat_intel_integration(self):
        """Connect threat intel to the analyzer"""
        # Add threat intel suspicious ports to analyzer
        self.analyzer.SUSPICIOUS_PORTS.update(self.threat_intel.suspicious_ports)
    
    def _packet_callback(self, packet_info, raw_packet=None):
        """Handle captured packets - SILENT mode (no terminal output)"""
        # Store packet
        self.captured_packets.append(packet_info)
        # Store raw packet reference on the PacketInfo for later inspection
        if raw_packet is not None:
            packet_info._raw = raw_packet
        if len(self.captured_packets) > self.max_stored_packets:
            self.captured_packets.pop(0)
        
        # Analyze and log alerts silently
        alerts = self.analyzer.analyze_packet(packet_info)
        for alert in alerts:
            self._log_alert(alert)
    
    def _log_alert(self, alert):
        """Log alert to file"""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"alerts_{datetime.now().strftime('%Y%m%d')}.log")
        with open(log_file, "a") as f:
            f.write(f"{alert.to_dict()}\n")
    
    def _print_alert(self, alert):
        """Print alert with formatting"""
        colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red"
        }
        color = colors.get(alert.threat_level.value, "white")
        
        self.console.print(f"\n⚠️  [{alert.threat_level.value.upper()}] {alert.alert_type}", style=color)
        self.console.print(f"   {alert.description}", style="white")
        self.console.print(f"   Source: {alert.source_ip} → {alert.destination_ip or 'N/A'}", style="dim")
    
    # === CAPTURE COMMANDS ===
    
    def do_start(self, arg):
        """Start packet capture. Usage: start [filter]
        Examples:
            start                    - Capture all traffic
            start 80                 - Capture port 80 (auto-expands to 'port 80')
            start tcp port 80        - Capture HTTP only
            start host 192.168.1.1   - Capture traffic to/from IP
        """
        if self.is_capturing:
            self.console.print("Already capturing. Use 'stop' first.", style="yellow")
            return
        
        bpf_filter = arg.strip() if arg else ""
        
        # Auto-expand bare port numbers to proper BPF syntax
        if bpf_filter and bpf_filter.isdigit():
            bpf_filter = f"port {bpf_filter}"
            self.console.print(f"   (expanded to '{bpf_filter}')", style="dim")
        
        self.sniffer.register_callback(self._packet_callback)
        self.sniffer.start(bpf_filter=bpf_filter)
        self.is_capturing = True
        
        self.console.print(f"✅ Started capture on {self.interface or 'default'}", style="green")
        if bpf_filter:
            self.console.print(f"   Filter: {bpf_filter}", style="dim")
        self.console.print("   Use 'watch' for live view, or continue using commands.", style="dim")
        self.console.print("   Alerts are logged silently. Use 'alerts' to view them.", style="dim")
    
    def do_watch(self, arg):
        """Watch live traffic. Press Ctrl+C to return to CLI.
        Usage: watch [mode]
        Modes:
            watch           - Split view (packets + alerts)
            watch packets   - Packets only
            watch alerts    - Alerts only
            watch full      - Full dashboard with stats
        """
        if not self.is_capturing:
            self.console.print("Start capture first with 'start'", style="yellow")
            return
        
        mode = arg.strip().lower() if arg else "both"
        
        # Handle 'full' mode separately - uses the dashboard module
        if mode == "full":
            self._run_full_dashboard()
            return
        
        self.console.print("Starting live watch... Press Ctrl+C to return to CLI\n", style="cyan")
        
        try:
            self._run_watch_mode(mode)
        except KeyboardInterrupt:
            pass
        
        if self.is_capturing:
            self.console.print("\n✅ Returned to CLI. Capture still running.", style="green")
            self.console.print("   Use 'stop' to stop, or 'watch' to resume.", style="dim")
        else:
            self.console.print("\n✅ Returned to CLI. Capture stopped.", style="yellow")
            self.console.print("   Use 'start' to begin capturing.", style="dim")
    
    def _run_watch_mode(self, mode: str = "both"):
        """Run the live watch display with interactive commands"""
        from collections import deque
        import time
        import sys
        import select
        import termios
        import tty
        
        # Local buffers for display
        recent_packets = deque(maxlen=15)
        recent_alerts = deque(maxlen=8)
        packet_count = [0]
        
        # Command state
        command_buffer = [""]
        command_feedback = [""]
        feedback_time = [None]
        filters = {"protocol": None, "port": None, "ip": None}
        running = [True]
        
        def watch_callback(pkt, raw_pkt=None):
            self._packet_callback(pkt, raw_pkt)
            packet_count[0] += 1
            recent_packets.append(pkt)
            if self.analyzer.alerts:
                latest = self.analyzer.alerts[-1]
                if latest not in recent_alerts:
                    recent_alerts.append(latest)
        
        def filter_packets(packets):
            result = list(packets)
            if filters["protocol"]:
                result = [p for p in result if p.protocol == filters["protocol"].upper()]
            if filters["port"]:
                result = [p for p in result if p.src_port == filters["port"] or p.dst_port == filters["port"]]
            if filters["ip"]:
                result = [p for p in result if filters["ip"] in p.src_ip or filters["ip"] in p.dst_ip]
            return result
        
        def process_command(cmd):
            parts = cmd.strip().split()
            if not parts:
                return ""
            command, args = parts[0].lower(), parts[1:] if len(parts) > 1 else []
            
            # === FILTERS ===
            if command == "proto":
                if not args or args[0] == "clear":
                    filters["protocol"] = None
                    return "✓ Protocol filter cleared"
                if args[0].upper() in ["TCP", "UDP", "ICMP", "DNS", "ARP"]:
                    filters["protocol"] = args[0].upper()
                    return f"✓ Filtering: {args[0].upper()}"
                return f"✗ Unknown: {args[0]}"
            elif command == "port":
                if not args or args[0] == "clear":
                    filters["port"] = None
                    return "✓ Port filter cleared"
                try:
                    filters["port"] = int(args[0])
                    return f"✓ Filtering: port {args[0]}"
                except:
                    return f"✗ Invalid port"
            elif command == "ip":
                if not args or args[0] == "clear":
                    filters["ip"] = None
                    return "✓ IP filter cleared"
                filters["ip"] = args[0]
                return f"✓ Filtering: {args[0]}"
            elif command == "clear":
                filters["protocol"] = filters["port"] = filters["ip"] = None
                return "✓ Filters cleared"
            
            # === ACTIONS ===
            elif command == "block" and args:
                result = self.actions.block_ip(args[0], "blocked from watch")
                geo = ""
                if geoip:
                    loc = geoip.lookup(args[0])
                    if loc:
                        geo = f" {geoip.get_country_flag(loc.country_code)}"
                return f"🚫 Blocked {args[0]}{geo}" if result["success"] else f"✗ {result.get('error', 'Failed')}"
            elif command == "unblock" and args:
                result = self.actions.unblock_ip(args[0])
                return f"✓ Unblocked {args[0]}" if result["success"] else f"✗ Failed"
            elif command == "whitelist" and args:
                self.actions.whitelist_ip(args[0])
                return f"✓ Whitelisted {args[0]}"
            
            # === GEO COMMANDS ===
            elif command == "geo" and args:
                if geoip:
                    loc = geoip.lookup(args[0])
                    if loc:
                        flag = geoip.get_country_flag(loc.country_code)
                        return f"{flag} {loc.city}, {loc.country} ({loc.isp})"
                    return f"✗ Could not locate {args[0]}"
                return "✗ GeoIP not available"
            elif command == "lookup" and args:
                info = self.actions.lookup_ip(args[0])
                blocked = "🚫" if info["blocked"] else ""
                white = "✅" if info["whitelisted"] else ""
                geo = ""
                if geoip:
                    loc = geoip.lookup(args[0])
                    if loc:
                        geo = f" {geoip.get_country_flag(loc.country_code)} {loc.short()}"
                return f"{blocked}{white}{geo}"
            
            # === VIEW COMMANDS ===
            elif command == "status":
                pkts = len(self.captured_packets)
                alerts = len(self.analyzer.alerts)
                return f"📊 Pkts:{pkts} Alerts:{alerts}"
            elif command == "alerts":
                count = len(self.analyzer.alerts)
                return f"⚠️ {count} total alerts"
            elif command == "top":
                talkers = self.analyzer._get_top_talkers(3)
                if not talkers:
                    return "No data"
                result = "🔝 "
                for t in talkers[:3]:
                    ip = t["ip"][:12]
                    mb = t["total_bytes"] / 1_000_000
                    result += f"{ip}:{mb:.1f}MB "
                return result
            
            # === CONTROL ===
            elif command == "start":
                if self.is_capturing:
                    return "Already capturing"
                self.sniffer.callbacks = [watch_callback]
                self.sniffer.start()
                self.is_capturing = True
                return "▶️ Capture started"
            
            elif command == "stop":
                if self.is_capturing:
                    self.sniffer.stop()
                    self.is_capturing = False
                    return "⏹️ Capture stopped"
                return "Not capturing"
            
            elif command == "full":
                # Switch to full dashboard mode
                running[0] = False
                switch_to_full[0] = True
                return "Switching to full dashboard..."
            
            elif command in ["quit", "q", "exit"]:
                running[0] = False
                return "Exiting..."
            elif command == "help":
                return "proto|port|ip|geo|block|status|top|start|stop|full|quit"
            
            return f"✗ Unknown: {command}"
        
        # Track if we should switch to full mode
        switch_to_full = [False]
        
        self.sniffer.callbacks = [watch_callback]
        
        def create_display():
            layout = Layout()
            
            # Header
            header = Text()
            header.append("🛡️ MERCUDS LIVE", style="bold cyan")
            header.append(f"  |  Packets: {packet_count[0]}", style="green")
            header.append(f"  |  Alerts: {len(self.analyzer.alerts)}", style="red" if self.analyzer.alerts else "dim")
            
            # Show active filters
            active = [f"{k}:{v}" for k, v in filters.items() if v]
            if active:
                header.append(f"  |  Filters: {', '.join(active)}", style="yellow")
            header.append("\n")
            
            # Show feedback or typing
            if command_feedback[0] and feedback_time[0] and (datetime.now() - feedback_time[0]).seconds < 2:
                header.append(command_feedback[0], style="green")
            else:
                header.append(f"› {command_buffer[0]}▌", style="cyan")
            
            # Packets table
            filtered = filter_packets(recent_packets)
            pkt_table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold blue")
            pkt_table.add_column("Time", width=8)
            pkt_table.add_column("Proto", width=5)
            pkt_table.add_column("Source", width=21)
            pkt_table.add_column("Destination", width=21)
            pkt_table.add_column("Size", width=6)
            
            for pkt in filtered:
                src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
                dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
                proto_colors = {"TCP": "cyan", "UDP": "green", "DNS": "blue", "ICMP": "yellow"}
                pkt_table.add_row(
                    pkt.timestamp.strftime("%H:%M:%S"),
                    f"[{proto_colors.get(pkt.protocol, 'white')}]{pkt.protocol}[/]",
                    src[:21], dst[:21], str(pkt.length)
                )
            
            # Alerts panel
            alert_content = Text()
            if recent_alerts:
                for alert in list(recent_alerts)[-5:]:
                    level_colors = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
                    alert_content.append(f"[{alert.timestamp.strftime('%H:%M:%S')}] ", style="dim")
                    alert_content.append(f"[{alert.threat_level.value.upper()}] ", style=level_colors.get(alert.threat_level.value, "white"))
                    alert_content.append(f"{alert.alert_type}\n", style="white")
            else:
                alert_content.append("No alerts", style="dim")
            
            filter_info = f" [{len(filtered)}/{len(recent_packets)}]" if active else ""
            
            if mode == "packets":
                layout.split_column(
                    Layout(Panel(header, box=box.ROUNDED), size=4),
                    Layout(Panel(pkt_table, title=f"📡 Packets{filter_info}", border_style="blue"))
                )
            elif mode == "alerts":
                layout.split_column(
                    Layout(Panel(header, box=box.ROUNDED), size=4),
                    Layout(Panel(alert_content, title="⚠️ Alerts", border_style="red"))
                )
            else:
                layout.split_column(
                    Layout(Panel(header, box=box.ROUNDED), size=4),
                    Layout(Panel(pkt_table, title=f"📡 Packets{filter_info}", border_style="blue"), ratio=2),
                    Layout(Panel(alert_content, title="⚠️ Alerts", border_style="yellow"), ratio=1)
                )
            
            return layout
        
        # Save and set terminal mode
        old_settings = termios.tcgetattr(sys.stdin)
        input_buffer = ""  # Buffer for handling escape sequences on macOS
        
        try:
            tty.setcbreak(sys.stdin.fileno())
            
            with Live(create_display(), refresh_per_second=4, console=self.console) as live:
                while running[0]:
                    # Read any available characters into buffer
                    if select.select([sys.stdin], [], [], 0)[0]:
                        input_buffer += sys.stdin.read(1)
                    
                    # Process buffer
                    while input_buffer:
                        if input_buffer[0] == '\x03':  # Ctrl+C
                            raise KeyboardInterrupt
                        elif input_buffer.startswith('\x1b['):
                            if len(input_buffer) >= 3:
                                # Complete arrow sequence - consume and ignore in simple mode
                                input_buffer = input_buffer[3:]
                            else:
                                # Incomplete, wait for more
                                break
                        elif input_buffer.startswith('\x1b'):
                            if len(input_buffer) == 1:
                                # Just ESC, wait
                                break
                            else:
                                # ESC + something else
                                input_buffer = input_buffer[1:]
                        elif input_buffer[0] in '\r\n':
                            if command_buffer[0].strip():
                                command_feedback[0] = process_command(command_buffer[0])
                                feedback_time[0] = datetime.now()
                            command_buffer[0] = ""
                            input_buffer = input_buffer[1:]
                        elif input_buffer[0] in '\x7f\x08':  # Backspace
                            command_buffer[0] = command_buffer[0][:-1]
                            input_buffer = input_buffer[1:]
                        elif input_buffer[0].isprintable():
                            command_buffer[0] += input_buffer[0]
                            input_buffer = input_buffer[1:]
                        else:
                            input_buffer = input_buffer[1:]
                    
                    # Handle bare ESC timeout
                    if input_buffer == '\x1b' and not select.select([sys.stdin], [], [], 0.03)[0]:
                        input_buffer = ""
                    
                    live.update(create_display())
                    time.sleep(0.03)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            self.sniffer.callbacks = [self._packet_callback]
        
        # Check if we should switch to full dashboard
        if switch_to_full[0]:
            self._run_full_dashboard()
    
    def _run_full_dashboard(self):
        """Run the full dashboard with stats panel"""
        self.console.print("Launching full dashboard... Press Ctrl+C to return\n", style="cyan")
        
        # Feed data to dashboard while also running silent callback
        def dashboard_callback(pkt, raw_pkt=None):
            # Run silent callback for storage/analysis
            self._packet_callback(pkt, raw_pkt)
            # Feed to dashboard with raw packet for inspection
            self.dashboard.add_packet(pkt, raw_pkt)
            # Check for new alerts
            if self.analyzer.alerts:
                latest = self.analyzer.alerts[-1]
                if latest not in list(self.dashboard.recent_alerts):
                    self.dashboard.add_alert(latest)
        
        # Command handler for dashboard commands - FULL CLI support
        def handle_dashboard_command(cmd: str, arg: str) -> str:
            # === ACTION COMMANDS ===
            if cmd == "block":
                result = self.actions.block_ip(arg, "blocked from dashboard")
                if result["success"]:
                    geo_info = ""
                    if geoip:
                        loc = geoip.lookup(arg)
                        if loc:
                            geo_info = f" {geoip.get_country_flag(loc.country_code)}"
                    return f"🚫 Blocked {arg}{geo_info}"
                return f"✗ {result.get('error', 'Failed')}"
            
            elif cmd == "unblock":
                result = self.actions.unblock_ip(arg)
                if result["success"]:
                    return f"✓ Unblocked {arg}"
                return f"✗ {result.get('error', 'Failed')}"
            
            elif cmd == "whitelist":
                result = self.actions.whitelist_ip(arg)
                return f"✓ Whitelisted {arg}"
            
            # === LOOKUP WITH GEO ===
            elif cmd == "lookup":
                info = self.actions.lookup_ip(arg)
                blocked = "🚫" if info["blocked"] else ""
                white = "✅" if info["whitelisted"] else ""
                geo_info = ""
                if geoip:
                    loc = geoip.lookup(arg)
                    if loc:
                        flag = geoip.get_country_flag(loc.country_code)
                        geo_info = f" {flag} {loc.short()}"
                dns = info.get('reverse_dns', '')[:15] if info.get('reverse_dns') else ""
                return f"{blocked}{white}{dns}{geo_info}"
            
            # === VIEW COMMANDS ===
            elif cmd == "status":
                pkts = len(self.captured_packets)
                alerts = len(self.analyzer.alerts)
                conns = len(self.analyzer.connections)
                blocked = len(self.actions.blocked_ips)
                return f"📊 Pkts:{pkts} Alerts:{alerts} Conns:{conns} Blocked:{blocked}"
            
            elif cmd == "alerts":
                count = int(arg) if arg.isdigit() else 5
                alerts = self.analyzer.alerts[-count:]
                if not alerts:
                    return "No alerts"
                types = {}
                for a in alerts:
                    types[a.alert_type] = types.get(a.alert_type, 0) + 1
                summary = ", ".join(f"{k}:{v}" for k, v in types.items())
                return f"⚠️ {len(alerts)} alerts: {summary}"
            
            elif cmd == "top":
                count = int(arg) if arg.isdigit() else 3
                talkers = self.analyzer._get_top_talkers(count)
                if not talkers:
                    return "No traffic data"
                result = "🔝 "
                for t in talkers[:3]:
                    mb = t["total_bytes"] / 1_000_000
                    ip = t["ip"]
                    geo = ""
                    if geoip:
                        loc = geoip.lookup(ip)
                        if loc:
                            geo = geoip.get_country_flag(loc.country_code)
                    result += f"{geo}{ip[:12]}:{mb:.1f}MB "
                return result
            
            elif cmd == "connections":
                conns = len(self.analyzer.connections)
                ips = len(self.analyzer.ip_stats)
                return f"🔗 {conns} connections, {ips} unique IPs"
            
            elif cmd == "threats":
                stats = self.threat_intel.get_stats()
                return f"🎯 {stats['total_indicators']} indicators, {stats['malicious_ips']} IPs"
            
            elif cmd == "blocked":
                blocked = self.actions.get_blocked_ips()
                if not blocked:
                    return "No IPs blocked"
                return f"🚫 Blocked: {', '.join(list(blocked)[:5])}" + ("..." if len(blocked) > 5 else "")
            
            # === EXPORT ===
            elif cmd == "export":
                if arg == "alerts":
                    result = self.actions.export_alerts(self.analyzer.alerts)
                    if result["success"]:
                        return f"💾 Exported {result['count']} alerts to {result['file']}"
                elif arg == "packets":
                    result = self.actions.export_packets(self.captured_packets)
                    if result["success"]:
                        return f"💾 Exported {result['count']} packets to {result['file']}"
                return f"✗ Export failed"
            
            # === THRESHOLD ===
            elif cmd == "threshold":
                parts = arg.split()
                if len(parts) >= 2:
                    name, value = parts[0], parts[1]
                    if name in self.analyzer.thresholds:
                        try:
                            self.analyzer.thresholds[name] = int(value)
                            return f"✓ {name}={value}"
                        except:
                            return f"✗ Invalid value"
                return f"✗ Usage: threshold <name> <value>"
            
            # === CONTROL ===
            elif cmd == "start":
                if self.is_capturing:
                    return "Already capturing"
                self.sniffer.callbacks = [dashboard_callback]
                self.sniffer.start()
                self.is_capturing = True
                return "▶️ Capture started"
            
            elif cmd == "stop":
                if self.is_capturing:
                    self.sniffer.stop()
                    self.is_capturing = False
                    return "⏹️ Capture stopped"
                return "Not capturing"
            
            return f"Unknown: {cmd}"
        
        # Set up dashboard
        self.dashboard.set_command_handler(handle_dashboard_command)
        self.sniffer.callbacks = [dashboard_callback]
        
        try:
            self.dashboard.start(get_summary_callback=self.analyzer.get_summary)
        except KeyboardInterrupt:
            pass
        finally:
            self.dashboard.stop()
            # Restore silent background callback
            self.sniffer.callbacks = [self._packet_callback]
            if self.is_capturing:
                self.console.print("\n✅ Returned to CLI. Capture still running.", style="green")
            else:
                self.console.print("\n✅ Returned to CLI. Capture stopped.", style="yellow")
    
    def do_stop(self, arg):
        """Stop packet capture"""
        if not self.is_capturing:
            self.console.print("Not currently capturing.", style="yellow")
            return
        
        self.sniffer.stop()
        self.is_capturing = False
        self.console.print("⏹️  Capture stopped.", style="yellow")
    
    def do_status(self, arg):
        """Show current status and statistics"""
        table = Table(title="📊 Current Status", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Capturing", "🟢 Yes" if self.is_capturing else "🔴 No")
        table.add_row("Interface", self.interface or "default")
        table.add_row("Packets Captured", str(len(self.captured_packets)))
        table.add_row("Total Alerts", str(len(self.analyzer.alerts)))
        table.add_row("Blocked IPs", str(len(self.actions.blocked_ips)))
        table.add_row("Connections Tracked", str(len(self.analyzer.connections)))
        
        self.console.print(table)
    
    # === VIEW COMMANDS ===
    
    def do_alerts(self, arg):
        """Show recent alerts. Usage: alerts [count]"""
        count = int(arg) if arg.isdigit() else 10
        alerts = self.analyzer.alerts[-count:]
        
        if not alerts:
            self.console.print("No alerts yet.", style="dim")
            return
        
        table = Table(title=f"⚠️  Recent Alerts (last {len(alerts)})", box=box.ROUNDED)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Level", width=8)
        table.add_column("Type", style="cyan", width=18)
        table.add_column("Source", width=15)
        table.add_column("Description", width=40)
        
        for alert in alerts:
            level_colors = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
            level_style = level_colors.get(alert.threat_level.value, "white")
            
            table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                f"[{level_style}]{alert.threat_level.value}[/]",
                alert.alert_type,
                alert.source_ip[:15],
                alert.description[:40]
            )
        
        self.console.print(table)
    
    def do_packets(self, arg):
        """Show recent packets. Usage: packets [count]"""
        count = int(arg) if arg.isdigit() else 10
        packets = self.captured_packets[-count:]
        
        if not packets:
            self.console.print("No packets captured yet.", style="dim")
            return
        
        table = Table(title=f"📦 Recent Packets (last {len(packets)})", box=box.ROUNDED)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Proto", width=6)
        table.add_column("Source", width=22)
        table.add_column("Destination", width=22)
        table.add_column("Size", width=6)
        
        for pkt in packets:
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
            
            table.add_row(
                pkt.timestamp.strftime("%H:%M:%S"),
                pkt.protocol,
                src[:22],
                dst[:22],
                str(pkt.length)
            )
        
        self.console.print(table)
    
    def do_connections(self, arg):
        """Show active connections"""
        conns = list(self.analyzer.connections.items())[:20]
        
        if not conns:
            self.console.print("No connections tracked yet.", style="dim")
            return
        
        table = Table(title="🔗 Top Connections", box=box.ROUNDED)
        table.add_column("Connection", style="cyan", width=40)
        table.add_column("Packets", width=10)
        table.add_column("Bytes", width=12)
        table.add_column("Ports", width=15)
        
        # Sort by packet count
        conns.sort(key=lambda x: x[1]["count"], reverse=True)
        
        for conn_key, data in conns[:20]:
            ports = list(data["ports"])[:5]
            ports_str = ",".join(str(p) for p in ports)
            if len(data["ports"]) > 5:
                ports_str += "..."
            
            table.add_row(
                conn_key[:40],
                str(data["count"]),
                f"{data['bytes']:,}",
                ports_str
            )
        
        self.console.print(table)
    
    def do_top(self, arg):
        """Show top talkers by traffic volume"""
        talkers = self.analyzer._get_top_talkers(10)
        
        if not talkers:
            self.console.print("No traffic data yet.", style="dim")
            return
        
        table = Table(title="🔝 Top Talkers", box=box.ROUNDED)
        table.add_column("IP Address", style="cyan", width=20)
        table.add_column("Total Traffic", width=15)
        
        for t in talkers:
            mb = t["total_bytes"] / 1_000_000
            table.add_row(t["ip"], f"{mb:.2f} MB")
        
        self.console.print(table)
    
    # === ACTION COMMANDS ===
    
    def do_block(self, arg):
        """Block an IP address. Usage: block <ip> [reason]"""
        parts = arg.split(maxsplit=1)
        if not parts:
            self.console.print("Usage: block <ip> [reason]", style="yellow")
            return
        
        ip = parts[0]
        reason = parts[1] if len(parts) > 1 else "manual block"
        
        result = self.actions.block_ip(ip, reason)
        if result["success"]:
            self.console.print(f"🚫 {result['message']}", style="green")
        else:
            self.console.print(f"❌ {result['error']}", style="red")
    
    def do_unblock(self, arg):
        """Unblock an IP address. Usage: unblock <ip>"""
        if not arg:
            self.console.print("Usage: unblock <ip>", style="yellow")
            return
        
        result = self.actions.unblock_ip(arg.strip())
        if result["success"]:
            self.console.print(f"✅ {result['message']}", style="green")
        else:
            self.console.print(f"❌ {result['error']}", style="red")
    
    def do_whitelist(self, arg):
        """Whitelist an IP (will never be blocked). Usage: whitelist <ip>"""
        if not arg:
            self.console.print("Usage: whitelist <ip>", style="yellow")
            return
        
        result = self.actions.whitelist_ip(arg.strip())
        self.console.print(f"✅ {result['message']}", style="green")
    
    def do_blocked(self, arg):
        """Show all blocked IPs"""
        blocked = self.actions.get_blocked_ips()
        
        if not blocked:
            self.console.print("No IPs currently blocked.", style="dim")
            return
        
        table = Table(title="🚫 Blocked IPs", box=box.ROUNDED)
        table.add_column("IP Address", style="red")
        
        for ip in blocked:
            table.add_row(ip)
        
        self.console.print(table)
    
    def do_lookup(self, arg):
        """Lookup information about an IP. Usage: lookup <ip>"""
        if not arg:
            self.console.print("Usage: lookup <ip>", style="yellow")
            return
        
        self.console.print(f"Looking up {arg}...", style="dim")
        info = self.actions.lookup_ip(arg.strip())
        
        table = Table(title=f"🔍 IP Lookup: {arg}", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Blocked", "🚫 Yes" if info["blocked"] else "No")
        table.add_row("Whitelisted", "✅ Yes" if info["whitelisted"] else "No")
        table.add_row("Reverse DNS", info["reverse_dns"] or "N/A")
        table.add_row("Route", info["route"] or "N/A")
        
        # Add GeoIP info
        if geoip:
            loc = geoip.lookup(arg.strip())
            if loc:
                flag = geoip.get_country_flag(loc.country_code)
                table.add_row("Location", f"{flag} {loc.city}, {loc.region}, {loc.country}")
                table.add_row("ISP", loc.isp)
                table.add_row("Organization", loc.org)
                table.add_row("Coordinates", f"{loc.lat}, {loc.lon}")
        
        self.console.print(table)
    
    def do_geo(self, arg):
        """GeoIP lookup for an IP address. Usage: geo <ip>"""
        if not arg:
            self.console.print("Usage: geo <ip>", style="yellow")
            return
        
        if not geoip:
            self.console.print("GeoIP not available", style="red")
            return
        
        ip = arg.strip()
        loc = geoip.lookup(ip)
        
        if not loc:
            self.console.print(f"Could not locate {ip}", style="red")
            return
        
        table = Table(title=f"🌍 GeoIP: {ip}", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        flag = geoip.get_country_flag(loc.country_code)
        table.add_row("Country", f"{flag} {loc.country} ({loc.country_code})")
        table.add_row("Region", loc.region)
        table.add_row("City", loc.city)
        table.add_row("Coordinates", f"{loc.lat}, {loc.lon}")
        table.add_row("ISP", loc.isp)
        table.add_row("Organization", loc.org)
        table.add_row("AS Number", loc.as_number)
        table.add_row("Private IP", "Yes" if loc.is_private else "No")
        
        self.console.print(table)
    
    # === EXPORT COMMANDS ===
    
    def do_export(self, arg):
        """Export data. Usage: export alerts|packets [filename]"""
        parts = arg.split()
        if not parts:
            self.console.print("Usage: export alerts|packets [filename]", style="yellow")
            return
        
        what = parts[0]
        filename = parts[1] if len(parts) > 1 else None
        
        if what == "alerts":
            result = self.actions.export_alerts(self.analyzer.alerts, filename)
        elif what == "packets":
            result = self.actions.export_packets(self.captured_packets, filename)
        else:
            self.console.print("Export 'alerts' or 'packets'", style="yellow")
            return
        
        if result["success"]:
            self.console.print(f"✅ Exported {result['count']} items to {result['file']}", style="green")
        else:
            self.console.print(f"❌ {result['error']}", style="red")
    
    # === THRESHOLD COMMANDS ===
    
    def do_thresholds(self, arg):
        """Show or set detection thresholds. Usage: thresholds [name value]"""
        if not arg:
            table = Table(title="⚙️  Detection Thresholds", box=box.ROUNDED)
            table.add_column("Threshold", style="cyan")
            table.add_column("Value", style="white")
            table.add_column("Description", style="dim")
            
            descs = {
                "port_scan_threshold": "Unique ports to trigger port scan alert",
                "connection_rate_threshold": "Connections/min to trigger flood alert",
                "data_exfil_threshold": "Bytes to trigger exfiltration alert",
                "time_window_seconds": "Time window for rate calculations"
            }
            
            for name, value in self.analyzer.thresholds.items():
                table.add_row(name, str(value), descs.get(name, ""))
            
            self.console.print(table)
        else:
            parts = arg.split()
            if len(parts) == 2:
                name, value = parts
                if name in self.analyzer.thresholds:
                    self.analyzer.thresholds[name] = int(value)
                    self.console.print(f"✅ Set {name} = {value}", style="green")
                else:
                    self.console.print(f"Unknown threshold: {name}", style="red")
    
    # === THREAT INTEL COMMANDS ===
    
    def do_threats(self, arg):
        """Show threat intelligence stats and detected threats
        Usage: threats [subcommand]
          threats             - Show stats overview
          threats ips         - List detected threat IPs from alerts
          threats alerts      - Show recent threat alerts
          threats indicators  - List all threat indicators (IPs in database)
          threats domains     - List malicious domains in database
          threats ports       - List suspicious ports in database
          threats check <ip>  - Check IP via AbuseIPDB
          threats scan        - Bulk scan all detected IPs via AbuseIPDB
          threats top [n]     - Show top N threats by severity
          threats add <type> <value> <threat> - Add indicator to database
          threats export [fmt]- Export threats to file (json/csv)
          threats clear [what]- Clear alerts or cache
          threats search <term> - Search across all threat data
        """
        parts = arg.strip().split(maxsplit=1)
        cmd = parts[0].lower() if parts else ""
        cmd_args = parts[1] if len(parts) > 1 else ""
        
        if cmd == "ips":
            self._show_threat_ips()
        elif cmd == "alerts":
            self._show_threat_alerts()
        elif cmd == "indicators" or cmd == "ind":
            self._show_threat_indicators()
        elif cmd == "domains" or cmd == "dom":
            self._show_threat_domains()
        elif cmd == "ports":
            self._show_threat_ports()
        elif cmd == "check":
            self._threats_check(cmd_args)
        elif cmd == "scan":
            self._threats_scan()
        elif cmd == "top":
            self._threats_top(cmd_args)
        elif cmd == "add":
            self.do_threat_add(cmd_args)
        elif cmd == "export":
            self._threats_export(cmd_args)
        elif cmd == "clear":
            self._threats_clear(cmd_args)
        elif cmd == "search":
            self._threats_search(cmd_args)
        elif cmd == "stats" or cmd == "":
            self._show_threat_stats()
        else:
            self.console.print("Usage: threats [ips|alerts|indicators|domains|ports|check|scan|top|add|export|clear|search]", style="yellow")
    
    def _show_threat_stats(self):
        """Show threat intelligence statistics"""
        stats = self.threat_intel.get_stats()
        
        table = Table(title="🎯 Threat Intelligence Database", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Command", style="dim")
        
        table.add_row("Total Indicators", str(stats["total_indicators"]), "threats indicators")
        table.add_row("Malicious IPs", str(stats["malicious_ips"]), "threats indicators")
        table.add_row("Malicious Domains", str(stats["malicious_domains"]), "threats domains")
        table.add_row("Suspicious Ports", str(stats["suspicious_ports"]), "threats ports")
        table.add_row("", "", "")
        table.add_row("Alerts Generated", str(len(self.analyzer.alerts)), "threats alerts")
        
        # Count unique threat IPs from alerts
        threat_ips = set()
        for alert in self.analyzer.alerts:
            if alert.source_ip and not alert.source_ip.startswith(("127.", "0.", "192.168.", "10.", "172.")):
                threat_ips.add(alert.source_ip)
            if alert.destination_ip and not alert.destination_ip.startswith(("127.", "0.", "192.168.", "10.", "172.")):
                threat_ips.add(alert.destination_ip)
        table.add_row("Detected Threat IPs", str(len(threat_ips)), "threats ips")
        
        self.console.print(table)
        self.console.print("\n💡 Use subcommand to view details", style="dim")
    
    def _show_threat_indicators(self):
        """Show all threat indicators (malicious IPs in database)"""
        indicators = list(self.threat_intel.indicators.values())
        
        if not indicators:
            self.console.print("No threat indicators in database.", style="yellow")
            return
        
        table = Table(title="📋 Threat Indicators Database", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Value", style="red")
        table.add_column("Threat Type", style="yellow")
        table.add_column("Confidence", style="magenta", justify="right")
        table.add_column("Source", style="dim")
        table.add_column("Description", style="white")
        
        for i, ind in enumerate(indicators, 1):
            conf = f"{ind.confidence:.0%}"
            table.add_row(
                str(i),
                ind.indicator_type.upper(),
                ind.value,
                ind.threat_type,
                conf,
                ind.source,
                ind.description[:30] if ind.description else "-"
            )
        
        self.console.print(table)
        self.console.print(f"\n📊 Total: {len(indicators)} indicators", style="dim")
        self.console.print("💡 Add more: threat_add <type> <value> <threat_type>", style="dim")
    
    def _show_threat_domains(self):
        """Show malicious domains in database"""
        domains = list(self.threat_intel.malicious_domains)
        
        if not domains:
            self.console.print("No malicious domains in database.", style="yellow")
            self.console.print("💡 Add: threat_add domain example.com malware", style="dim")
            return
        
        table = Table(title="🌐 Malicious Domains", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Domain", style="red")
        table.add_column("Threat Type", style="yellow")
        table.add_column("Description", style="white")
        
        for i, domain in enumerate(sorted(domains), 1):
            # Find the indicator for details
            key = f"domain:{domain}"
            ind = self.threat_intel.indicators.get(key)
            threat_type = ind.threat_type if ind else "-"
            desc = ind.description[:40] if ind and ind.description else "-"
            
            table.add_row(str(i), domain, threat_type, desc)
        
        self.console.print(table)
        self.console.print(f"\n📊 Total: {len(domains)} domains", style="dim")
    
    def _show_threat_ports(self):
        """Show suspicious ports in database"""
        ports = self.threat_intel.suspicious_ports
        
        if not ports:
            self.console.print("No suspicious ports configured.", style="yellow")
            return
        
        table = Table(title="🔌 Suspicious Ports", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Port", style="red", justify="right")
        table.add_column("Description", style="yellow")
        
        for i, (port, desc) in enumerate(sorted(ports.items()), 1):
            table.add_row(str(i), str(port), desc)
        
        self.console.print(table)
        self.console.print(f"\n📊 Total: {len(ports)} suspicious ports", style="dim")
        self.console.print("💡 Add more: port_add <port> <description>", style="dim")
    
    def _show_threat_ips(self):
        """Show list of detected threat IPs"""
        # Collect IPs from alerts with their threat info
        ip_threats = defaultdict(lambda: {"count": 0, "types": set(), "levels": set()})
        
        for alert in self.analyzer.alerts:
            # Track source IPs (attackers)
            if alert.source_ip:
                ip_threats[alert.source_ip]["count"] += 1
                ip_threats[alert.source_ip]["types"].add(alert.alert_type)
                ip_threats[alert.source_ip]["levels"].add(alert.threat_level.value)
            
        if not ip_threats:
            self.console.print("No threat IPs detected yet.", style="yellow")
            return
        
        # Sort by count (most active threats first)
        sorted_ips = sorted(ip_threats.items(), key=lambda x: x[1]["count"], reverse=True)
        
        table = Table(title="🚨 Detected Threat IPs", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("IP Address", style="red")
        table.add_column("Alerts", style="yellow", justify="right")
        table.add_column("Threat Types", style="cyan")
        table.add_column("Max Level", style="magenta")
        table.add_column("Status", style="white")
        
        for i, (ip, data) in enumerate(sorted_ips[:30], 1):  # Top 30
            types = ", ".join(sorted(data["types"]))[:30]
            max_level = max(data["levels"]) if data["levels"] else "low"
            
            # Check if blocked/whitelisted
            status = ""
            if ip in self.actions.blocked_ips:
                status = "🚫 BLOCKED"
            elif ip in self.actions.whitelist:
                status = "✅ Whitelisted"
            else:
                status = "⚠️ Active"
            
            level_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "white"}.get(max_level, "white")
            
            table.add_row(
                str(i),
                ip,
                str(data["count"]),
                types,
                f"[{level_style}]{max_level}[/]",
                status
            )
        
        self.console.print(table)
        self.console.print(f"\n📊 Total: {len(ip_threats)} unique IPs", style="dim")
        self.console.print("💡 Use: block <ip> | lookup <ip> | threat_check <ip>", style="dim")
    
    def _show_threat_alerts(self):
        """Show recent threat alerts"""
        alerts = self.analyzer.alerts[-50:]  # Last 50
        
        if not alerts:
            self.console.print("No alerts generated yet.", style="yellow")
            return
        
        table = Table(title="🚨 Recent Threat Alerts", box=box.ROUNDED)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Level", style="white", width=8)
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Source IP", style="red")
        table.add_column("Dest IP", style="yellow")
        table.add_column("Description", style="white")
        
        for alert in reversed(alerts[-20:]):  # Show last 20
            level = alert.threat_level.value
            level_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "white"}.get(level, "white")
            
            table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                f"[{level_style}]{level.upper()}[/]",
                alert.alert_type,
                alert.source_ip or "-",
                alert.destination_ip or "-",
                alert.description[:40]
            )
        
        self.console.print(table)
        self.console.print(f"\n📊 Showing {min(20, len(alerts))} of {len(self.analyzer.alerts)} total alerts", style="dim")
    
    def _threats_check(self, ip: str):
        """Check a single IP via AbuseIPDB (threats check <ip>)"""
        if not ip:
            self.console.print("Usage: threats check <ip>", style="yellow")
            return
        self.do_threat_check(ip)
    
    def _threats_scan(self):
        """Bulk scan all detected threat IPs via AbuseIPDB"""
        if not self.threat_intel.abuseipdb_api_key:
            self.console.print("❌ No AbuseIPDB API key configured", style="red")
            self.console.print("💡 Set with: abuseipdb_key <your_key>", style="dim")
            return
        
        # Collect unique external IPs from alerts
        ips_to_check = set()
        for alert in self.analyzer.alerts:
            for ip in [alert.source_ip, alert.destination_ip]:
                if ip and not ip.startswith(("127.", "0.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                    ips_to_check.add(ip)
        
        if not ips_to_check:
            self.console.print("No external IPs detected yet. Start capturing traffic first.", style="yellow")
            return
        
        self.console.print(f"🔍 Scanning {len(ips_to_check)} unique IPs via AbuseIPDB...", style="cyan")
        
        results = []
        malicious_count = 0
        
        from rich.progress import Progress
        with Progress(console=self.console) as progress:
            task = progress.add_task("Checking IPs...", total=len(ips_to_check))
            
            for ip in ips_to_check:
                result = self.threat_intel.check_ip_abuseipdb(ip)
                if result:
                    results.append(result)
                    if result.is_malicious:
                        malicious_count += 1
                progress.advance(task)
        
        if results:
            results.sort(key=lambda r: r.abuse_confidence_score, reverse=True)
            
            table = Table(title=f"🔍 AbuseIPDB Scan ({malicious_count} malicious)", box=box.ROUNDED)
            table.add_column("IP", style="white")
            table.add_column("Score", justify="right")
            table.add_column("Level")
            table.add_column("Country", style="dim")
            table.add_column("Reports", justify="right")
            table.add_column("ISP", style="dim")
            
            for r in results[:30]:
                score_style = "red bold" if r.abuse_confidence_score >= 80 else "red" if r.abuse_confidence_score >= 50 else "yellow" if r.abuse_confidence_score > 0 else "green"
                level_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}.get(r.threat_level, "white")
                
                table.add_row(
                    r.ip,
                    f"[{score_style}]{r.abuse_confidence_score}%[/]",
                    f"[{level_style}]{r.threat_level.upper()}[/]",
                    r.country_code or "-",
                    str(r.total_reports),
                    (r.isp[:25] + "..") if r.isp and len(r.isp) > 25 else (r.isp or "-")
                )
            
            self.console.print(table)
            self.console.print(f"\n📊 Scanned {len(results)} IPs: {malicious_count} malicious", style="dim")
        else:
            self.console.print("⚠️  No results (rate limited or API error)", style="yellow")
    
    def _threats_top(self, args: str):
        """Show top N threats ranked by severity and frequency"""
        try:
            n = int(args) if args else 10
        except ValueError:
            n = 10
        
        ip_scores = defaultdict(lambda: {"score": 0, "count": 0, "max_level": "low", "types": set()})
        level_weights = {"critical": 100, "high": 50, "medium": 20, "low": 5}
        
        for alert in self.analyzer.alerts:
            ip = alert.source_ip
            if ip:
                level = alert.threat_level.value
                weight = level_weights.get(level, 5)
                ip_scores[ip]["score"] += weight
                ip_scores[ip]["count"] += 1
                ip_scores[ip]["types"].add(alert.alert_type)
                if level_weights.get(level, 0) > level_weights.get(ip_scores[ip]["max_level"], 0):
                    ip_scores[ip]["max_level"] = level
        
        if not ip_scores:
            self.console.print("No threats detected yet.", style="yellow")
            return
        
        sorted_threats = sorted(ip_scores.items(), key=lambda x: x[1]["score"], reverse=True)[:n]
        
        table = Table(title=f"🏆 Top {n} Threats", box=box.ROUNDED)
        table.add_column("Rank", style="dim", width=4)
        table.add_column("IP Address", style="red")
        table.add_column("Score", style="magenta", justify="right")
        table.add_column("Alerts", style="yellow", justify="right")
        table.add_column("Max Level")
        table.add_column("Types", style="cyan")
        table.add_column("Status")
        
        for i, (ip, data) in enumerate(sorted_threats, 1):
            level_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "white"}.get(data["max_level"], "white")
            status = "🚫 BLOCKED" if ip in self.actions.blocked_ips else "⚠️ Active"
            types = ", ".join(sorted(data["types"]))[:30]
            
            table.add_row(
                str(i), ip, str(data["score"]), str(data["count"]),
                f"[{level_style}]{data['max_level'].upper()}[/]",
                types, status
            )
        
        self.console.print(table)
        self.console.print("💡 Use: threats check <ip> | block <ip>", style="dim")
    
    def _threats_export(self, format_arg: str):
        """Export threat data to file"""
        import json
        
        fmt = format_arg.lower() if format_arg else "json"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "alerts": [],
            "detected_ips": [],
            "indicators": []
        }
        
        for alert in self.analyzer.alerts:
            export_data["alerts"].append({
                "timestamp": alert.timestamp.isoformat(),
                "type": alert.alert_type,
                "level": alert.threat_level.value,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "description": alert.description
            })
        
        ip_stats = defaultdict(lambda: {"count": 0, "types": [], "levels": []})
        for alert in self.analyzer.alerts:
            if alert.source_ip:
                ip_stats[alert.source_ip]["count"] += 1
                ip_stats[alert.source_ip]["types"].append(alert.alert_type)
                ip_stats[alert.source_ip]["levels"].append(alert.threat_level.value)
        
        for ip, stats in ip_stats.items():
            export_data["detected_ips"].append({
                "ip": ip, "alert_count": stats["count"],
                "types": list(set(stats["types"])),
                "max_level": max(stats["levels"]) if stats["levels"] else "low"
            })
        
        for ind in self.threat_intel.indicators.values():
            export_data["indicators"].append({
                "type": ind.indicator_type, "value": ind.value,
                "threat_type": ind.threat_type, "confidence": ind.confidence,
                "source": ind.source
            })
        
        if fmt == "json":
            filename = f"threat_export_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)
            self.console.print(f"✅ Exported to {filename}", style="green")
            self.console.print(f"   {len(export_data['alerts'])} alerts, {len(export_data['detected_ips'])} IPs", style="dim")
        elif fmt == "csv":
            filename = f"threat_ips_{timestamp}.csv"
            with open(filename, "w") as f:
                f.write("ip,alert_count,types,max_level\n")
                for d in export_data["detected_ips"]:
                    f.write(f"{d['ip']},{d['alert_count']},\"{','.join(d['types'])}\",{d['max_level']}\n")
            self.console.print(f"✅ Exported to {filename}", style="green")
        else:
            self.console.print("Usage: threats export [json|csv]", style="yellow")
    
    def _threats_clear(self, what: str):
        """Clear threat alerts or cache"""
        what = what.lower() if what else ""
        
        if what == "alerts":
            count = len(self.analyzer.alerts)
            self.analyzer.alerts.clear()
            self.console.print(f"✅ Cleared {count} alerts", style="green")
        elif what == "cache":
            if hasattr(self.threat_intel, '_abuseipdb_cache'):
                count = len(self.threat_intel._abuseipdb_cache)
                self.threat_intel._abuseipdb_cache.clear()
                self.console.print(f"✅ Cleared {count} cached lookups", style="green")
            else:
                self.console.print("No cache to clear", style="yellow")
        elif what == "all":
            alert_count = len(self.analyzer.alerts)
            self.analyzer.alerts.clear()
            cache_count = 0
            if hasattr(self.threat_intel, '_abuseipdb_cache'):
                cache_count = len(self.threat_intel._abuseipdb_cache)
                self.threat_intel._abuseipdb_cache.clear()
            self.console.print(f"✅ Cleared {alert_count} alerts, {cache_count} cached lookups", style="green")
        else:
            self.console.print("Usage: threats clear [alerts|cache|all]", style="yellow")
    
    def _threats_search(self, term: str):
        """Search across all threat data"""
        if not term:
            self.console.print("Usage: threats search <term>", style="yellow")
            return
        
        term = term.lower()
        results = []
        
        for alert in self.analyzer.alerts:
            if (term in (alert.source_ip or "").lower() or 
                term in (alert.destination_ip or "").lower() or
                term in alert.alert_type.lower() or
                term in alert.description.lower()):
                results.append(("alert", alert))
        
        for ind in self.threat_intel.indicators.values():
            if (term in ind.value.lower() or 
                term in ind.threat_type.lower() or
                term in (ind.description or "").lower()):
                results.append(("indicator", ind))
        
        for domain in self.threat_intel.malicious_domains:
            if term in domain.lower():
                results.append(("domain", domain))
        
        if not results:
            self.console.print(f"No results for '{term}'", style="yellow")
            return
        
        self.console.print(f"🔍 Found {len(results)} matches for '{term}':\n", style="cyan")
        
        alerts = [d for t, d in results if t == "alert"]
        indicators = [d for t, d in results if t == "indicator"]
        domains = [d for t, d in results if t == "domain"]
        
        if alerts:
            self.console.print(f"[bold]Alerts ({len(alerts)}):[/bold]")
            for alert in alerts[:10]:
                level_style = {"critical": "red", "high": "red", "medium": "yellow"}.get(alert.threat_level.value, "dim")
                self.console.print(f"  [{level_style}]{alert.alert_type}[/] {alert.source_ip} → {alert.destination_ip}")
        
        if indicators:
            self.console.print(f"\n[bold]Indicators ({len(indicators)}):[/bold]")
            for ind in indicators[:10]:
                self.console.print(f"  [red]{ind.value}[/] ({ind.threat_type})")
        
        if domains:
            self.console.print(f"\n[bold]Domains ({len(domains)}):[/bold]")
            for domain in domains[:10]:
                self.console.print(f"  [red]{domain}[/]")

    def do_threat_add(self, arg):
        """Add a threat indicator. Usage: threat_add <type> <value> <threat_type>
        Types: ip, domain, port
        Example: threat_add ip 1.2.3.4 malware
        """
        parts = arg.split()
        if len(parts) < 3:
            self.console.print("Usage: threat_add <type> <value> <threat_type>", style="yellow")
            self.console.print("  Types: ip, domain", style="dim")
            self.console.print("  Threat types: malware, c2, scanner, botnet", style="dim")
            return
        
        ind_type, value, threat_type = parts[0], parts[1], parts[2]
        
        indicator = ThreatIndicator(
            indicator_type=ind_type,
            value=value,
            threat_type=threat_type,
            confidence=0.8,
            source="manual",
            last_updated=datetime.now(),
            description=f"Manually added via CLI"
        )
        
        self.threat_intel.add_indicator(indicator)
        self.console.print(f"✅ Added {ind_type} indicator: {value} ({threat_type})", style="green")
    
    def do_threat_check(self, arg):
        """Check IP against local database AND AbuseIPDB
        Usage: threat_check <ip>
        """
        if not arg:
            self.console.print("Usage: threat_check <ip>", style="yellow")
            return
        
        value = arg.strip()
        
        # Check local database first
        local_result = self.threat_intel.check_ip(value)
        if local_result:
            self.console.print(f"⚠️  FOUND IN LOCAL DATABASE!", style="bold red")
            table = Table(title="Local Threat Intel", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Type", local_result.indicator_type)
            table.add_row("Value", local_result.value)
            table.add_row("Threat Type", local_result.threat_type)
            table.add_row("Confidence", f"{local_result.confidence:.0%}")
            table.add_row("Source", local_result.source)
            table.add_row("Description", local_result.description)
            self.console.print(table)
        else:
            self.console.print(f"✅ {value} not in local database", style="green")
        
        # Check AbuseIPDB
        if self.threat_intel.abuseipdb_api_key:
            self.console.print("\n🔍 Checking AbuseIPDB...", style="dim")
            abuse_result = self.threat_intel.check_ip_abuseipdb(value)
            
            if abuse_result:
                if abuse_result.is_malicious:
                    style = "bold red"
                    status = "⚠️  MALICIOUS"
                elif abuse_result.abuse_confidence_score > 0:
                    style = "yellow"
                    status = "⚡ SUSPICIOUS"
                else:
                    style = "green"
                    status = "✅ CLEAN"
                
                self.console.print(f"\n{status} - AbuseIPDB Score: {abuse_result.abuse_confidence_score}%", style=style)
                
                table = Table(title="🌐 AbuseIPDB Result", box=box.ROUNDED)
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                table.add_row("IP Address", abuse_result.ip)
                table.add_row("Abuse Score", f"{abuse_result.abuse_confidence_score}%")
                table.add_row("Threat Level", abuse_result.threat_level.upper())
                table.add_row("Country", abuse_result.country_code or "-")
                table.add_row("ISP", abuse_result.isp[:40] if abuse_result.isp else "-")
                table.add_row("Domain", abuse_result.domain or "-")
                table.add_row("Total Reports", str(abuse_result.total_reports))
                if abuse_result.last_reported:
                    table.add_row("Last Reported", abuse_result.last_reported.strftime("%Y-%m-%d %H:%M"))
                if abuse_result.category_names:
                    table.add_row("Categories", ", ".join(abuse_result.category_names[:5]))
                table.add_row("Whitelisted", "Yes" if abuse_result.is_whitelisted else "No")
                self.console.print(table)
                
                if abuse_result.is_malicious and not local_result:
                    self.console.print("\n💡 Auto-added to local threat database", style="dim green")
            else:
                self.console.print("⚠️  AbuseIPDB lookup failed (rate limited or error)", style="yellow")
        else:
            self.console.print("\n💡 Set AbuseIPDB API key for real-time threat intel: abuseipdb_key <key>", style="dim")
    
    def do_abuseipdb_key(self, arg):
        """Set AbuseIPDB API key for real-time threat lookups
        Usage: abuseipdb_key <your_api_key>
        
        Get a free API key at: https://www.abuseipdb.com/account/api
        Free tier: 1000 checks/day
        """
        if not arg:
            if self.threat_intel.abuseipdb_api_key:
                masked = self.threat_intel.abuseipdb_api_key[:8] + "..." + self.threat_intel.abuseipdb_api_key[-4:]
                self.console.print(f"✅ AbuseIPDB API key configured: {masked}", style="green")
            else:
                self.console.print("❌ No AbuseIPDB API key configured", style="yellow")
                self.console.print("\nGet a free key at: https://www.abuseipdb.com/account/api", style="dim")
                self.console.print("Usage: abuseipdb_key <your_api_key>", style="dim")
            return
        
        api_key = arg.strip()
        self.threat_intel.set_abuseipdb_key(api_key)
        self.console.print("✅ AbuseIPDB API key saved!", style="green")
        self.console.print("   You can now use threat_check <ip> for real-time lookups", style="dim")
    
    def do_ports(self, arg):
        """Show suspicious ports being monitored"""
        table = Table(title="🚪 Suspicious Ports", box=box.ROUNDED)
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Reason", style="white")
        
        for port, reason in sorted(self.threat_intel.suspicious_ports.items()):
            table.add_row(str(port), reason)
        
        self.console.print(table)
    
    def do_port_add(self, arg):
        """Add a suspicious port. Usage: port_add <port> <reason>"""
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            self.console.print("Usage: port_add <port> <reason>", style="yellow")
            return
        
        try:
            port = int(parts[0])
            reason = parts[1]
            self.threat_intel.suspicious_ports[port] = reason
            self.analyzer.SUSPICIOUS_PORTS[port] = reason
            self.console.print(f"✅ Added suspicious port {port}: {reason}", style="green")
        except ValueError:
            self.console.print("Port must be a number", style="red")
    
    # === MENU / HELP ===
    
    def do_menu(self, arg):
        """Show quick command menu"""
        menu = """
╔═══════════════════════════════════════════════════════════════════════╗
║                         📋 COMMAND MENU                               ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  📡 CAPTURE & WATCH                    🔍 VIEW DATA                   ║
║  ──────────────────                    ───────────                    ║
║  start [filter]  - Begin capture       alerts     - View alerts       ║
║  stop            - Stop capture        packets    - View packets      ║
║  status          - Show stats          connections- View connections  ║
║                                         top        - Top talkers       ║
║  watch           - Live split view                                    ║
║  watch packets   - Live packets only                                  ║
║  watch alerts    - Live alerts only                                   ║
║  watch full      - Full dashboard                                     ║
║                                                                       ║
║  🚫 ACTIONS                            🎯 THREAT INTEL                ║
║  ──────────                            ─────────────                  ║
║  block <ip>      - Block IP            threats    - Threat stats      ║
║  unblock <ip>    - Unblock IP          threats ips/ports/indicators   ║
║  whitelist <ip>  - Whitelist IP        threat_check <ip> - Check IP   ║
║  blocked         - List blocked        threat_add - Add indicator     ║
║  lookup <ip>     - IP info             abuseipdb_key - Set API key    ║
║                                                                       ║
║  💾 EXPORT & CONFIG                                                   ║
║  ──────────────────                                                   ║
║  export alerts   - Save alerts         thresholds - Detection limits  ║
║  export packets  - Save packets        clear      - Clear screen      ║
║                                         quit       - Exit program      ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
        self.console.print(menu)
    
    # === UTILITY COMMANDS ===
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('clear')
    
    def do_quit(self, arg):
        """Exit the program"""
        if self.is_capturing:
            self.sniffer.stop()
        
        # Print final summary like main.py does
        self._print_final_summary()
        
        self.console.print("\n👋 Goodbye!\n", style="cyan")
        return True
    
    def _print_final_summary(self):
        """Print final statistics summary"""
        stats = self.sniffer.get_stats()
        summary = self.analyzer.get_summary()
        
        self.console.print("\n")
        table = Table(title="📊 Final Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Total Packets", str(stats.get('total_packets', 0)))
        table.add_row("Runtime", f"{stats.get('runtime_seconds', 0):.1f} seconds")
        table.add_row("Avg Rate", f"{stats.get('packets_per_second', 0):.1f} packets/sec")
        table.add_row("Total Alerts", str(summary['total_alerts']))
        table.add_row("Unique IPs", str(summary['unique_ips']))
        table.add_row("Connections", str(summary['total_connections']))
        table.add_row("Blocked IPs", str(len(self.actions.blocked_ips)))
        
        self.console.print(table)
        
        if summary['alerts_by_severity']:
            alert_table = Table(title="⚠️ Alerts by Severity", box=box.ROUNDED)
            alert_table.add_column("Level", style="cyan")
            alert_table.add_column("Count", style="white")
            for level, count in summary['alerts_by_severity'].items():
                alert_table.add_row(level.upper(), str(count))
            self.console.print(alert_table)
    
    def do_exit(self, arg):
        """Exit the program"""
        return self.do_quit(arg)
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        self.console.print(f"Unknown command: {line}. Type 'help' for commands.", style="yellow")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Mercuds Interactive Mode")
    parser.add_argument("-i", "--interface", help="Network interface")
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("⚠️  Warning: Run with sudo for packet capture")
        print("   sudo python interactive.py -i en0\n")
    
    cli = MercudsCLI(interface=args.interface)
    cli.cmdloop()


if __name__ == "__main__":
    main()
