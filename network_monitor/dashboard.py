"""
Real-time Dashboard Module
Terminal-based UI for monitoring network activity
"""

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.progress_bar import ProgressBar
from rich import box
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Optional, Callable
import threading
import time
import sys
import select
import termios
import tty

# Import GeoIP
try:
    from geoip import geoip, GeoIPLookup
except ImportError:
    geoip = None


class Dashboard:
    """
    Real-time terminal dashboard for network monitoring
    """
    
    THREAT_COLORS = {
        "low": "green",
        "medium": "yellow", 
        "high": "red",
        "critical": "bold red on white"
    }
    
    def __init__(self, max_packets: int = 20, max_alerts: int = 10):
        self.console = Console()
        self.max_packets = max_packets
        self.max_alerts = max_alerts
        
        # Circular buffers for display
        self.recent_packets = deque(maxlen=max_packets)
        self.recent_alerts = deque(maxlen=max_alerts)
        
        # Stats
        self.stats = {
            "total_packets": 0,
            "packets_per_sec": 0,
            "total_alerts": 0,
            "start_time": None,
            "bytes_in": 0,
            "bytes_out": 0
        }
        
        # Rate calculation
        self._packet_times = deque(maxlen=100)
        
        # Enhanced metrics
        self._rate_history = deque(maxlen=60)  # 60 samples for sparkline
        self._protocol_counts = defaultdict(int)
        self._port_counts = defaultdict(int)
        self._alert_weights = {"low": 1, "medium": 3, "high": 7, "critical": 15}
        self._threat_score = 0
        self._threat_score_decay = 0.95  # Decay factor per update
        self._last_rate_sample = datetime.now()
        
        self._running = False
        self._live: Optional[Live] = None
        
        # Interactive command support
        self._command_buffer = ""
        self._command_history = deque(maxlen=20)
        self._command_feedback = ""
        self._feedback_time = None
        self._filters = {
            "protocol": None,  # e.g., "TCP", "UDP"
            "port": None,      # e.g., 443
            "ip": None,        # e.g., "192.168.1.1"
            "country": None,   # e.g., "US", "CN"
        }
        self._command_handler: Optional[Callable] = None
        
        # GeoIP cache for packets
        self._geo_cache = {}
        
        # === LAYOUT CONTROL (Problem 1) ===
        self._visible_panels = {
            "alerts": True,
            "stats": True,
            "metrics": True,
        }
        self._zoom_level = 1  # 1=normal, 2=more rows, 3=compact
        self._focus_panel = None  # None or "packets", "alerts", etc.
        
        # === PACKET SELECTION (Problem 2) ===
        self._frozen = False  # Pause live updates
        self._frozen_packets = []  # Snapshot of packets when frozen
        self._selected_index = 0  # Currently highlighted packet
        self._viewing_packet = None  # Packet being viewed in detail
        self._scroll_offset = 0  # For scrolling through packets
        self._all_packets = deque(maxlen=500)  # Larger buffer for frozen mode
        self._raw_packets = {}  # Store raw scapy packets for inspection
    
    def add_packet(self, packet_info, raw_packet=None):
        """Add a packet to the display buffer"""
        # Assign packet number
        packet_info.packet_num = self.stats["total_packets"] + 1
        
        self.recent_packets.append(packet_info)
        self._all_packets.append(packet_info)
        self.stats["total_packets"] += 1
        self._packet_times.append(datetime.now())
        self._update_rate()
        
        # Store raw packet for inspection
        if raw_packet is not None:
            self._raw_packets[packet_info.packet_num] = raw_packet
            # Limit raw packet storage
            if len(self._raw_packets) > 200:
                oldest = min(self._raw_packets.keys())
                del self._raw_packets[oldest]
        
        # Track protocol distribution
        self._protocol_counts[packet_info.protocol] += 1
        
        # Track port activity
        if packet_info.dst_port:
            self._port_counts[packet_info.dst_port] += 1
        if packet_info.src_port:
            self._port_counts[packet_info.src_port] += 1
        
        # Track bandwidth (estimate: src_ip is local = outbound)
        self.stats["bytes_out"] += packet_info.length
    
    def add_alert(self, alert):
        """Add an alert to the display buffer"""
        self.recent_alerts.append(alert)
        self.stats["total_alerts"] += 1
        
        # Update threat score based on alert severity
        weight = self._alert_weights.get(alert.threat_level.value, 1)
        self._threat_score = min(100, self._threat_score + weight)
    
    def _update_rate(self):
        """Calculate packets per second and update history"""
        if len(self._packet_times) < 2:
            return
        
        time_span = (self._packet_times[-1] - self._packet_times[0]).total_seconds()
        if time_span > 0:
            self.stats["packets_per_sec"] = len(self._packet_times) / time_span
        
        # Sample rate every second for sparkline
        now = datetime.now()
        if (now - self._last_rate_sample).total_seconds() >= 1:
            self._rate_history.append(self.stats["packets_per_sec"])
            self._last_rate_sample = now
            
            # Decay threat score over time
            self._threat_score = max(0, self._threat_score * self._threat_score_decay)
    
    def _create_header(self) -> Panel:
        """Create the header panel"""
        runtime = ""
        if self.stats["start_time"]:
            elapsed = datetime.now() - self.stats["start_time"]
            runtime = str(elapsed).split('.')[0]
        
        header_text = Text()
        header_text.append("🛡️  MERCUDS NETWORK MONITOR  🛡️", style="bold cyan")
        
        # Show frozen status
        if self._frozen:
            header_text.append("  [FROZEN]", style="bold yellow on red")
        header_text.append("\n")
        
        header_text.append(f"Runtime: {runtime}  |  ", style="white")
        header_text.append(f"Packets: {self.stats['total_packets']}  |  ", style="green")
        header_text.append(f"Rate: {self.stats['packets_per_sec']:.1f}/s  |  ", style="yellow")
        header_text.append(f"Alerts: {self.stats['total_alerts']}  |  ", style="red")
        
        # Show threat score with color
        score = int(self._threat_score)
        threat_color = self._get_threat_color()
        header_text.append(f"Threat: {score}/100", style=threat_color)
        
        return Panel(header_text, box=box.DOUBLE)
    
    def _create_packet_table(self) -> Panel:
        """Create the packet display table with selection support"""
        # Determine how many rows based on zoom level
        rows_per_zoom = {1: self.max_packets, 2: 30, 3: 50}
        max_rows = rows_per_zoom.get(self._zoom_level, self.max_packets)
        
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE,
            expand=True
        )
        
        # Add packet number column when frozen
        if self._frozen:
            table.add_column("#", width=4, style="dim")
        table.add_column("Time", width=8)
        table.add_column("Proto", width=5)
        table.add_column("Source", width=22)
        table.add_column("Destination", width=22)
        table.add_column("Size", width=6)
        
        # Use frozen snapshot or live buffer
        source_packets = self._frozen_packets if self._frozen else list(self.recent_packets)
        
        # Apply filters
        filtered_packets = self._filter_packets(source_packets)
        
        # Apply scroll offset in frozen mode
        if self._frozen and self._scroll_offset > 0:
            start = max(0, len(filtered_packets) - max_rows - self._scroll_offset)
            end = len(filtered_packets) - self._scroll_offset
            display_packets = filtered_packets[start:end]
        else:
            display_packets = filtered_packets[-max_rows:]
        
        for idx, pkt in enumerate(reversed(display_packets)):
            pkt_num = getattr(pkt, 'packet_num', idx)
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
            
            # Add country flags if geo available
            if geoip:
                src_loc = self._get_cached_geo(pkt.src_ip)
                dst_loc = self._get_cached_geo(pkt.dst_ip)
                if src_loc:
                    src = f"{geoip.get_country_flag(src_loc.country_code)}{src[:19]}"
                if dst_loc:
                    dst = f"{geoip.get_country_flag(dst_loc.country_code)}{dst[:19]}"
            
            proto_color = {
                "TCP": "cyan",
                "UDP": "green",
                "ICMP": "yellow",
                "DNS": "blue",
                "ARP": "magenta"
            }.get(pkt.protocol, "white")
            
            # Highlight selected packet in frozen mode
            # Calculate actual index in original list
            actual_idx = len(filtered_packets) - len(display_packets) + idx
            is_selected = self._frozen and actual_idx == self._selected_index
            row_style = "bold reverse" if is_selected else ""
            
            if self._frozen:
                table.add_row(
                    f"{pkt_num}",
                    pkt.timestamp.strftime("%H:%M:%S"),
                    f"[{proto_color}]{pkt.protocol}[/]",
                    src[:22],
                    dst[:22],
                    f"{pkt.length}",
                    style=row_style
                )
            else:
                table.add_row(
                    pkt.timestamp.strftime("%H:%M:%S"),
                    f"[{proto_color}]{pkt.protocol}[/]",
                    src[:22],
                    dst[:22],
                    f"{pkt.length}"
                )
        
        # Build title
        filter_info = ""
        active = [f"{k}:{v}" for k,v in self._filters.items() if v]
        if active:
            filter_info = f" [{len(filtered_packets)}/{len(source_packets)}]"
        
        mode = ""
        page_info = ""
        if self._frozen:
            # Calculate page info
            total_packets = len(filtered_packets)
            page_size = max_rows
            total_pages = max(1, (total_packets + page_size - 1) // page_size)
            current_page = total_pages - (self._scroll_offset // page_size)
            page_info = f" [Page {current_page}/{total_pages}]"
            mode = " 🧊 FROZEN - n/p=page, view <n>, resume"
        
        return Panel(table, title=f"📡 Packets{filter_info}{page_info}{mode}", border_style="blue" if not self._frozen else "yellow")
    
    def _filter_packets(self, packets: list) -> list:
        """Apply current filters to packet list"""
        result = packets
        
        if self._filters["protocol"]:
            proto = self._filters["protocol"].upper()
            result = [p for p in result if p.protocol == proto]
        
        if self._filters["port"]:
            port = self._filters["port"]
            result = [p for p in result if p.src_port == port or p.dst_port == port]
        
        if self._filters["ip"]:
            ip = self._filters["ip"]
            result = [p for p in result if ip in p.src_ip or ip in p.dst_ip]
        
        if self._filters["country"] and geoip:
            country = self._filters["country"]
            filtered = []
            for p in result:
                # Check source IP country
                src_loc = self._get_cached_geo(p.src_ip)
                dst_loc = self._get_cached_geo(p.dst_ip)
                if (src_loc and src_loc.country_code == country) or \
                   (dst_loc and dst_loc.country_code == country):
                    filtered.append(p)
            result = filtered
        
        return result
    
    def _get_cached_geo(self, ip: str):
        """Get geo location with caching"""
        if ip not in self._geo_cache and geoip:
            self._geo_cache[ip] = geoip.lookup(ip)
        return self._geo_cache.get(ip)
    
    def _create_packet_detail_panel(self, pkt_idx: int) -> Panel:
        """Create detailed view of selected packet"""
        # Use frozen snapshot if available, otherwise all_packets
        packet_list = self._frozen_packets if self._frozen else list(self._all_packets)
        
        if pkt_idx < 0 or pkt_idx >= len(packet_list):
            return Panel(Text("No packet selected", style="dim"), title="📦 Packet Details")
        
        pkt = packet_list[pkt_idx]
        pkt_num = getattr(pkt, 'packet_num', pkt_idx + 1)
        content = Text()
        
        # Header info
        content.append(f"📦 Packet #{pkt_num}\n", style="bold cyan")
        content.append(f"Time: {pkt.timestamp.strftime('%H:%M:%S.%f')[:-3]}  ", style="white")
        content.append(f"Size: {pkt.length} bytes  ", style="green")
        content.append(f"Protocol: {pkt.protocol}\n\n", style="yellow")
        
        # Network layer
        content.append("🔹 NETWORK LAYER\n", style="bold blue")
        src_geo = ""
        dst_geo = ""
        if geoip:
            src_loc = self._get_cached_geo(pkt.src_ip)
            dst_loc = self._get_cached_geo(pkt.dst_ip)
            if src_loc:
                src_geo = f" {geoip.get_country_flag(src_loc.country_code)} {src_loc.short()}"
            if dst_loc:
                dst_geo = f" {geoip.get_country_flag(dst_loc.country_code)} {dst_loc.short()}"
        
        content.append(f"   Source:      {pkt.src_ip}{src_geo}\n", style="white")
        content.append(f"   Destination: {pkt.dst_ip}{dst_geo}\n\n", style="white")
        
        # Transport layer
        content.append("🔹 TRANSPORT LAYER\n", style="bold blue")
        content.append(f"   Protocol:    {pkt.protocol}\n", style="white")
        if pkt.src_port:
            content.append(f"   Src Port:    {pkt.src_port}\n", style="white")
        if pkt.dst_port:
            port_name = self._get_port_name(pkt.dst_port)
            content.append(f"   Dst Port:    {pkt.dst_port}", style="white")
            if port_name:
                content.append(f" ({port_name})", style="dim")
            content.append("\n")
        if hasattr(pkt, 'flags') and pkt.flags:
            content.append(f"   Flags:       {pkt.flags}\n", style="white")
        
        # Raw packet info if available
        raw_pkt = self._raw_packets.get(pkt_num)
        if raw_pkt:
            content.append("\n🔹 RAW PACKET LAYERS\n", style="bold blue")
            try:
                # Show layer summary
                layers = []
                layer = raw_pkt
                while layer:
                    layers.append(layer.name)
                    layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
                    if hasattr(layer, 'name') and layer.name == 'Raw':
                        break
                content.append(f"   Layers: {' → '.join(layers[:6])}\n", style="cyan")
                
                # Show hex dump (first 64 bytes)
                content.append("\n🔹 HEX DUMP (first 64 bytes)\n", style="bold blue")
                raw_bytes = bytes(raw_pkt)[:64]
                for i in range(0, len(raw_bytes), 16):
                    chunk = raw_bytes[i:i+16]
                    hex_str = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    content.append(f"   {i:04x}: {hex_str:<48} {ascii_str}\n", style="dim")
            except Exception as e:
                content.append(f"   Error parsing: {e}\n", style="red")
        
        content.append("\n[Esc or 'back' to return]", style="dim italic")
        
        return Panel(content, title=f"📦 Packet #{pkt_num} Details", border_style="cyan")
    
    def _create_alert_panel(self) -> Panel:
        """Create the alerts panel"""
        if not self.recent_alerts:
            return Panel(
                Text("No alerts detected", style="dim"),
                title="⚠️  Alerts",
                border_style="green"
            )
        
        alert_text = Text()
        for alert in reversed(list(self.recent_alerts)):
            color = self.THREAT_COLORS.get(alert.threat_level.value, "white")
            alert_text.append(f"[{alert.timestamp.strftime('%H:%M:%S')}] ", style="dim")
            alert_text.append(f"[{alert.threat_level.value.upper()}] ", style=color)
            alert_text.append(f"{alert.alert_type}: ", style="bold")
            alert_text.append(f"{alert.description}\n", style="white")
            alert_text.append(f"    Source: {alert.source_ip}", style="dim")
            if alert.destination_ip:
                alert_text.append(f" → {alert.destination_ip}", style="dim")
            alert_text.append("\n\n")
        
        border_color = "red" if self.recent_alerts else "green"
        return Panel(alert_text, title="⚠️  Alerts", border_style=border_color)
    
    def _create_sparkline(self) -> str:
        """Create ASCII sparkline from rate history"""
        if not self._rate_history:
            return "No data yet"
        
        # Sparkline characters (from low to high)
        chars = "▁▂▃▄▅▆▇█"
        
        values = list(self._rate_history)
        if not values:
            return "─" * 30
        
        max_val = max(values) if max(values) > 0 else 1
        min_val = min(values)
        range_val = max_val - min_val if max_val != min_val else 1
        
        sparkline = ""
        for v in values[-30:]:  # Last 30 samples
            idx = int((v - min_val) / range_val * (len(chars) - 1))
            sparkline += chars[idx]
        
        return sparkline
    
    def _get_threat_color(self) -> str:
        """Get color based on threat score"""
        if self._threat_score >= 70:
            return "bold red"
        elif self._threat_score >= 40:
            return "red"
        elif self._threat_score >= 20:
            return "yellow"
        elif self._threat_score >= 10:
            return "green"
        return "dim green"
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    
    def _create_metrics_panel(self) -> Panel:
        """Create the enhanced metrics panel with all 5 features"""
        content = Text()
        
        # 1. Traffic Graph (Sparkline)
        content.append("📈 Traffic Rate (60s)\n", style="bold cyan")
        sparkline = self._create_sparkline()
        content.append(f"   {sparkline}\n", style="green")
        content.append(f"   Current: {self.stats['packets_per_sec']:.1f} pkt/s\n\n", style="dim")
        
        # 2. Threat Score
        content.append("🎯 Threat Score\n", style="bold cyan")
        score = int(self._threat_score)
        score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
        threat_color = self._get_threat_color()
        content.append(f"   [{score_bar}] ", style=threat_color)
        content.append(f"{score}/100\n\n", style=threat_color)
        
        # 3. Protocol Breakdown
        content.append("📊 Protocols\n", style="bold cyan")
        total_proto = sum(self._protocol_counts.values()) or 1
        proto_colors = {"TCP": "cyan", "UDP": "green", "DNS": "blue", "ICMP": "yellow", "ARP": "magenta"}
        sorted_protos = sorted(self._protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for proto, count in sorted_protos:
            pct = (count / total_proto) * 100
            bar_len = int(pct / 5)
            color = proto_colors.get(proto, "white")
            content.append(f"   {proto:5} ", style=color)
            content.append(f"{'▓' * bar_len}{'░' * (20-bar_len)} {pct:5.1f}%\n", style=color)
        content.append("\n")
        
        # 4. Top Ports
        content.append("🚪 Top Ports\n", style="bold cyan")
        sorted_ports = sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for port, count in sorted_ports:
            port_name = self._get_port_name(port)
            content.append(f"   {port:5} ", style="yellow")
            content.append(f"{port_name:12} ", style="dim")
            content.append(f"{count:,}\n", style="white")
        content.append("\n")
        
        # 5. Bandwidth Counter
        content.append("💾 Bandwidth\n", style="bold cyan")
        content.append(f"   Total: {self._format_bytes(self.stats['bytes_out'])}\n", style="green")
        
        return Panel(content, title="⚡ Live Metrics", border_style="magenta")
    
    def _get_port_name(self, port: int) -> str:
        """Get common port name"""
        port_names = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return port_names.get(port, "")
    
    def _create_stats_panel(self, analyzer_summary: Optional[dict] = None) -> Panel:
        """Create statistics panel"""
        stats_text = Text()
        
        if analyzer_summary:
            stats_text.append("📊 Connection Stats\n", style="bold")
            stats_text.append(f"  Unique IPs: {analyzer_summary.get('unique_ips', 0)}\n")
            stats_text.append(f"  Connections: {analyzer_summary.get('total_connections', 0)}\n\n")
            
            stats_text.append("🔝 Top Talkers\n", style="bold")
            for talker in analyzer_summary.get('top_talkers', [])[:5]:
                mb = talker['total_bytes'] / 1_000_000
                stats_text.append(f"  {talker['ip']}: {mb:.2f} MB\n")
            
            stats_text.append("\n📈 Alerts by Type\n", style="bold")
            for alert_type, count in analyzer_summary.get('alerts_by_type', {}).items():
                stats_text.append(f"  {alert_type}: {count}\n")
        else:
            stats_text.append("Collecting data...", style="dim")
        
        return Panel(stats_text, title="📊 Statistics", border_style="cyan")
    
    def _create_command_bar(self) -> Panel:
        """Create the interactive command bar with context-sensitive help"""
        content = Text()
        
        # Show active filters
        active_filters = []
        if self._filters["protocol"]:
            active_filters.append(f"proto:{self._filters['protocol']}")
        if self._filters["port"]:
            active_filters.append(f"port:{self._filters['port']}")
        if self._filters["ip"]:
            active_filters.append(f"ip:{self._filters['ip']}")
        if self._filters.get("country"):
            active_filters.append(f"🌍{self._filters['country']}")
        
        if active_filters:
            content.append("Filters: ", style="dim")
            content.append(" | ".join(active_filters), style="yellow")
            content.append("  ", style="dim")
        
        # Show feedback message if recent
        if self._command_feedback and self._feedback_time:
            if (datetime.now() - self._feedback_time).seconds < 3:
                content.append(f"{self._command_feedback}  ", style="green")
        
        # Show command prompt
        content.append("\n› ", style="bold cyan")
        content.append(self._command_buffer, style="white")
        content.append("▌", style="bold cyan")  # Cursor
        
        # Context-sensitive help
        content.append("\n", style="dim")
        
        if self._viewing_packet is not None:
            content.append("back | n=next | p=prev | resume | quit", style="dim italic")
        elif self._frozen:
            content.append("n=next | p=prev | top | bottom | page <n> | view <n> | resume | quit", style="dim italic")
        else:
            content.append("freeze | n/p=page | top | view <n> | zoom | hide/show | start|stop | quit", style="dim italic")
        
        return Panel(content, title="⌨️  Command", border_style="green", height=5)
    
    def generate_layout(self, analyzer_summary: Optional[dict] = None) -> Layout:
        """Generate the full dashboard layout with enhanced metrics and panel controls"""
        layout = Layout()
        
        # Check if viewing a specific packet detail
        if self._viewing_packet is not None and self._viewing_packet < len(self._all_packets):
            # Full screen packet detail view
            layout.split_column(
                Layout(name="header", size=5),
                Layout(name="detail"),
                Layout(name="command", size=5)
            )
            layout["header"].update(self._create_header())
            layout["detail"].update(self._create_packet_detail_panel(self._viewing_packet))
            layout["command"].update(self._create_command_bar())
            return layout
        
        # Apply zoom levels
        if self._zoom_level == 3:
            # Zoom 3: Full screen packets only
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="packets"),
                Layout(name="command", size=5)
            )
            layout["header"].update(self._create_header())
            layout["packets"].update(self._create_packet_table())
            layout["command"].update(self._create_command_bar())
            return layout
        
        elif self._zoom_level == 2:
            # Zoom 2: Packets and alerts, no right panel
            layout.split_column(
                Layout(name="header", size=4),
                Layout(name="body"),
                Layout(name="command", size=5)
            )
            layout["body"].split_column(
                Layout(name="packets", ratio=2),
                Layout(name="alerts", ratio=1)
            )
            layout["header"].update(self._create_header())
            layout["packets"].update(self._create_packet_table())
            layout["alerts"].update(self._create_alert_panel())
            layout["command"].update(self._create_command_bar())
            return layout
        
        # Zoom 1: Normal layout with panel visibility
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body"),
            Layout(name="command", size=5)
        )
        
        # Determine visible panels
        show_alerts = self._visible_panels.get("alerts", True)
        show_stats = self._visible_panels.get("stats", True)
        show_metrics = self._visible_panels.get("metrics", True)
        show_right = show_stats or show_metrics
        
        if show_right:
            layout["body"].split_row(
                Layout(name="left", ratio=3),
                Layout(name="right", ratio=2)
            )
            
            # Left side
            if show_alerts:
                layout["left"].split_column(
                    Layout(name="packets", ratio=2),
                    Layout(name="alerts", ratio=1)
                )
            else:
                layout["left"].update(self._create_packet_table())
            
            # Right side
            if show_stats and show_metrics:
                layout["right"].split_column(
                    Layout(name="metrics", ratio=2),
                    Layout(name="stats", ratio=1)
                )
            elif show_metrics:
                layout["right"].update(self._create_metrics_panel())
            elif show_stats:
                layout["right"].update(self._create_stats_panel(analyzer_summary))
        else:
            # No right panel
            if show_alerts:
                layout["body"].split_column(
                    Layout(name="packets", ratio=2),
                    Layout(name="alerts", ratio=1)
                )
            else:
                layout["body"].update(self._create_packet_table())
        
        # Update all visible sections
        layout["header"].update(self._create_header())
        layout["command"].update(self._create_command_bar())
        
        # Update panels that exist
        try:
            if show_right:
                if show_alerts:
                    layout["left"]["packets"].update(self._create_packet_table())
                    layout["left"]["alerts"].update(self._create_alert_panel())
                if show_stats and show_metrics:
                    layout["right"]["metrics"].update(self._create_metrics_panel())
                    layout["right"]["stats"].update(self._create_stats_panel(analyzer_summary))
            else:
                if show_alerts:
                    layout["body"]["packets"].update(self._create_packet_table())
                    layout["body"]["alerts"].update(self._create_alert_panel())
        except KeyError:
            pass  # Panel doesn't exist in this configuration
        
        return layout
    
    def set_command_handler(self, handler: Callable):
        """Set external command handler for commands like 'block'"""
        self._command_handler = handler
    
    def _process_command(self, cmd: str) -> str:
        """Process a command and return feedback message"""
        parts = cmd.strip().split()
        if not parts:
            return ""
        
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # === FILTER COMMANDS ===
        
        # Protocol filter
        if command == "proto":
            if not args or args[0] == "clear":
                self._filters["protocol"] = None
                return "✓ Protocol filter cleared"
            proto = args[0].upper()
            if proto in ["TCP", "UDP", "ICMP", "DNS", "ARP"]:
                self._filters["protocol"] = proto
                return f"✓ Filtering: {proto} only"
            return f"✗ Unknown protocol: {args[0]}"
        
        # Port filter
        elif command == "port":
            if not args or args[0] == "clear":
                self._filters["port"] = None
                return "✓ Port filter cleared"
            try:
                port = int(args[0])
                self._filters["port"] = port
                return f"✓ Filtering: port {port}"
            except ValueError:
                return f"✗ Invalid port: {args[0]}"
        
        # IP filter
        elif command == "ip":
            if not args or args[0] == "clear":
                self._filters["ip"] = None
                return "✓ IP filter cleared"
            self._filters["ip"] = args[0]
            return f"✓ Filtering: {args[0]}"
        
        # Country filter (new!)
        elif command == "country":
            if not args or args[0] == "clear":
                self._filters["country"] = None
                return "✓ Country filter cleared"
            self._filters["country"] = args[0].upper()
            return f"✓ Filtering: country {args[0].upper()}"
        
        # Clear all filters
        elif command == "clear":
            self._filters = {"protocol": None, "port": None, "ip": None, "country": None}
            return "✓ All filters cleared"
        
        # === ACTION COMMANDS ===
        
        # Block IP
        elif command == "block":
            if not args:
                return "✗ Usage: block <ip>"
            if self._command_handler:
                return self._command_handler("block", args[0])
            return f"✓ Block request: {args[0]}"
        
        # Unblock IP
        elif command == "unblock":
            if not args:
                return "✗ Usage: unblock <ip>"
            if self._command_handler:
                return self._command_handler("unblock", args[0])
            return f"✓ Unblock request: {args[0]}"
        
        # Whitelist IP
        elif command == "whitelist":
            if not args:
                return "✗ Usage: whitelist <ip>"
            if self._command_handler:
                return self._command_handler("whitelist", args[0])
            return f"✓ Whitelist request: {args[0]}"
        
        # === GEO COMMANDS ===
        
        # GeoIP lookup
        elif command == "geo":
            if not args:
                return "✗ Usage: geo <ip>"
            if geoip:
                loc = geoip.lookup(args[0])
                if loc:
                    flag = geoip.get_country_flag(loc.country_code)
                    return f"{flag} {loc.city}, {loc.country} ({loc.isp})"
                return f"✗ Could not locate {args[0]}"
            return "✗ GeoIP not available"
        
        # Lookup IP (with geo)
        elif command == "lookup":
            if not args:
                return "✗ Usage: lookup <ip>"
            result = ""
            if self._command_handler:
                result = self._command_handler("lookup", args[0])
            if geoip:
                loc = geoip.lookup(args[0])
                if loc:
                    flag = geoip.get_country_flag(loc.country_code)
                    result += f" {flag} {loc.short()}"
            return result or f"Lookup: {args[0]}"
        
        # === VIEW COMMANDS ===
        
        # Status
        elif command == "status":
            if self._command_handler:
                return self._command_handler("status", "")
            pkts = self.stats["total_packets"]
            alerts = self.stats["total_alerts"]
            return f"📊 Pkts:{pkts} Alerts:{alerts} Rate:{self.stats['packets_per_sec']:.1f}/s"
        
        # Alerts summary
        elif command == "alerts":
            if self._command_handler:
                return self._command_handler("alerts", args[0] if args else "5")
            return f"⚠️ Total alerts: {self.stats['total_alerts']}"
        
        # Top talkers
        elif command == "top":
            if self._command_handler:
                return self._command_handler("top", args[0] if args else "3")
            return "Use 'top' in CLI for full list"
        
        # Connections
        elif command == "connections" or command == "conns":
            if self._command_handler:
                return self._command_handler("connections", "")
            return "Use 'connections' in CLI for full list"
        
        # Threats
        elif command == "threats":
            if self._command_handler:
                return self._command_handler("threats", "")
            return "Use 'threats' in CLI for full list"
        
        # Blocked IPs
        elif command == "blocked":
            if self._command_handler:
                return self._command_handler("blocked", "")
            return "Use 'blocked' in CLI for full list"
        
        # === EXPORT COMMANDS ===
        
        elif command == "export":
            if not args:
                return "✗ Usage: export alerts|packets"
            if self._command_handler:
                return self._command_handler("export", args[0])
            return f"Export: {args[0]}"
        
        # === THRESHOLD COMMANDS ===
        
        elif command == "threshold":
            if len(args) < 2:
                return "✗ Usage: threshold <name> <value>"
            if self._command_handler:
                return self._command_handler("threshold", f"{args[0]} {args[1]}")
            return f"Set {args[0]}={args[1]}"
        
        # === LAYOUT COMMANDS ===
        
        # Hide panel
        elif command == "hide":
            if not args:
                return "✗ Usage: hide alerts|stats|metrics"
            panel = args[0].lower()
            if panel in self._visible_panels:
                self._visible_panels[panel] = False
                return f"✓ Hidden: {panel}"
            return f"✗ Unknown panel: {panel} (use: alerts, stats, metrics)"
        
        # Show panel
        elif command == "show":
            if not args:
                return "✗ Usage: show alerts|stats|metrics|all"
            panel = args[0].lower()
            if panel == "all":
                for p in self._visible_panels:
                    self._visible_panels[p] = True
                return "✓ All panels visible"
            if panel in self._visible_panels:
                self._visible_panels[panel] = True
                return f"✓ Showing: {panel}"
            return f"✗ Unknown panel: {panel}"
        
        # Zoom level
        elif command == "zoom":
            if not args:
                return f"Current zoom: {self._zoom_level} (1=full, 2=wide, 3=packets only)"
            try:
                level = int(args[0])
                if 1 <= level <= 3:
                    self._zoom_level = level
                    zoom_names = {1: "Full layout", 2: "Wide packets", 3: "Packets only"}
                    return f"✓ Zoom {level}: {zoom_names[level]}"
                return "✗ Zoom must be 1, 2, or 3"
            except ValueError:
                return "✗ Usage: zoom <1-3>"
        
        # === PACKET SELECTION COMMANDS ===
        
        # Freeze packets
        elif command == "freeze" or command == "f":
            self._frozen = True
            self._frozen_packets = list(self._all_packets)  # Take snapshot
            self._selected_index = len(self._frozen_packets) - 1 if self._frozen_packets else -1
            return f"❄️ Frozen {len(self._frozen_packets)} packets! scroll/view <n>/resume"
        
        # Resume live updates
        elif command == "resume" or command == "r":
            self._frozen = False
            self._frozen_packets = []  # Clear snapshot
            self._viewing_packet = None
            self._selected_index = -1
            self._scroll_offset = 0
            return "▶️ Resumed live packet capture"
        
        # View packet detail
        elif command == "view" or command == "v":
            if not args:
                return "✗ Usage: view <packet_number> - View packet by its # number"
            try:
                pkt_num = int(args[0])
                # Find packet by its packet_num (shown in # column)
                packet_list = self._frozen_packets if self._frozen else list(self._all_packets)
                for idx, pkt in enumerate(packet_list):
                    if getattr(pkt, 'packet_num', idx + 1) == pkt_num:
                        self._viewing_packet = idx
                        if not self._frozen:
                            self._frozen = True
                            self._frozen_packets = list(self._all_packets)
                        return f"📋 Viewing packet #{pkt_num}"
                # Show available range
                if packet_list:
                    first_num = getattr(packet_list[0], 'packet_num', 1)
                    last_num = getattr(packet_list[-1], 'packet_num', len(packet_list))
                    return f"✗ Packet #{pkt_num} not found. Available: #{first_num}-#{last_num}"
                return "✗ No packets captured yet"
            except ValueError:
                return "✗ Usage: view <packet_number>"
        
        # Go back from detail view
        elif command == "back" or command == "b":
            if self._viewing_packet is not None:
                self._viewing_packet = None
                return "← Back to packet list"
            return "Not in detail view"
        
        # Search/find packet
        elif command == "find" or command == "search":
            if not args:
                return "✗ Usage: find <ip|port|string>"
            query = args[0].lower()
            for i, pkt in enumerate(self._all_packets):
                # Build searchable string from packet attributes
                pkt_str = f"{pkt.src_ip} {pkt.dst_ip} {pkt.src_port or ''} {pkt.dst_port or ''} {pkt.protocol}".lower()
                if query in pkt_str:
                    self._frozen = True
                    self._selected_index = i
                    return f"🔍 Found at #{i + 1}: {pkt.src_ip} → {pkt.dst_ip}"
            return f"✗ Not found: {query}"
        
        # === CONTROL COMMANDS ===
        
        # Start capture
        elif command == "start":
            if self._command_handler:
                return self._command_handler("start", "")
            return "✗ Start not available"
        
        # Stop capture
        elif command == "stop":
            if self._command_handler:
                return self._command_handler("stop", "")
            return "✗ Stop not available"
        
        # === PAGE NAVIGATION (CLI-based) ===
        
        # Next page of packets
        elif command in ["next", "n", "more"]:
            if not self._frozen:
                self._frozen = True
                self._frozen_packets = list(self._all_packets)
            amount = int(args[0]) if args else 10
            max_offset = max(0, len(self._frozen_packets) - 10)
            self._scroll_offset = min(self._scroll_offset + amount, max_offset)
            # Calculate current page
            page_size = 10
            total_pages = max(1, (len(self._frozen_packets) + page_size - 1) // page_size)
            current_page = total_pages - (self._scroll_offset // page_size)
            return f"▲ Page {current_page}/{total_pages} (older)"
        
        # Previous page (towards newer)
        elif command in ["prev", "p", "back"]:
            if self._viewing_packet is not None:
                self._viewing_packet = None
                return "← Back to packet list"
            amount = int(args[0]) if args else 10
            self._scroll_offset = max(0, self._scroll_offset - amount)
            # Calculate current page
            total = len(self._frozen_packets) if self._frozen else len(self._all_packets)
            page_size = 10
            total_pages = max(1, (total + page_size - 1) // page_size)
            current_page = total_pages - (self._scroll_offset // page_size)
            return f"▼ Page {current_page}/{total_pages} (newer)"
        
        # Jump to top (oldest)
        elif command == "top" or command == "oldest":
            if not self._frozen:
                self._frozen = True
                self._frozen_packets = list(self._all_packets)
            self._scroll_offset = max(0, len(self._frozen_packets) - 10)
            total_pages = max(1, (len(self._frozen_packets) + 9) // 10)
            return f"⏫ Page 1/{total_pages} (oldest)"
        
        # Jump to bottom (newest/latest)
        elif command in ["bottom", "latest", "end"]:
            self._scroll_offset = 0
            total = len(self._frozen_packets) if self._frozen else len(self._all_packets)
            total_pages = max(1, (total + 9) // 10)
            return f"⏬ Page {total_pages}/{total_pages} (latest)"
        
        # Go to specific page
        elif command == "page" or command == "goto":
            if not args:
                total = len(self._frozen_packets) if self._frozen else len(self._all_packets)
                page_size = 10
                current_page = (self._scroll_offset // page_size) + 1
                total_pages = max(1, (total + page_size - 1) // page_size)
                return f"Page {current_page}/{total_pages}. Use: page <n>"
            try:
                page_num = int(args[0])
                if not self._frozen:
                    self._frozen = True
                    self._frozen_packets = list(self._all_packets)
                page_size = 10
                total_pages = max(1, (len(self._frozen_packets) + page_size - 1) // page_size)
                page_num = max(1, min(page_num, total_pages))
                self._scroll_offset = (total_pages - page_num) * page_size
                return f"📄 Page {page_num}/{total_pages}"
            except ValueError:
                return "✗ Usage: page <number>"
        
        # Quit dashboard
        elif command in ["quit", "q", "exit"]:
            self._running = False
            return "Exiting dashboard..."
        
        # Help
        elif command == "help" or command == "?":
            if self._viewing_packet is not None:
                return "back|next|prev|resume|quit"
            elif self._frozen:
                return "next|prev|top|bottom|page <n>|view <n>|resume|start|stop|quit"
            else:
                return "freeze|next|prev|top|view <n>|zoom|hide/show|start|stop|quit"
        
        else:
            return f"✗ Unknown: {command}. Type 'help'"
    
    def _read_char_nonblocking(self) -> Optional[str]:
        """Read a single character without blocking"""
        if select.select([sys.stdin], [], [], 0)[0]:
            return sys.stdin.read(1)
        return None
    
    def start(self, get_summary_callback=None):
        """Start the live dashboard with interactive command support"""
        self.stats["start_time"] = datetime.now()
        self._running = True
        
        # Save terminal settings
        old_settings = termios.tcgetattr(sys.stdin)
        
        try:
            # Set terminal to raw mode for character-by-character input
            tty.setcbreak(sys.stdin.fileno())
            
            with Live(self.generate_layout(), refresh_per_second=4, console=self.console) as live:
                self._live = live
                while self._running:
                    # Read keyboard input
                    char = self._read_char_nonblocking()
                    if char:
                        if char == '\x03':  # Ctrl+C
                            raise KeyboardInterrupt
                        elif char in '\r\n':  # Enter
                            if self._command_buffer.strip():
                                feedback = self._process_command(self._command_buffer)
                                self._command_feedback = feedback
                                self._feedback_time = datetime.now()
                                self._command_history.append(self._command_buffer)
                            self._command_buffer = ""
                        elif char in '\x7f\x08':  # Backspace
                            self._command_buffer = self._command_buffer[:-1]
                        elif char == '\x1b':  # Escape - just ignore escape sequences
                            # Consume any following escape sequence characters
                            while select.select([sys.stdin], [], [], 0.01)[0]:
                                sys.stdin.read(1)
                        elif char.isprintable():
                            self._command_buffer += char
                    
                    # Update display
                    summary = get_summary_callback() if get_summary_callback else None
                    live.update(self.generate_layout(summary))
                    time.sleep(0.05)
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    
    def stop(self):
        """Stop the dashboard"""
        self._running = False
