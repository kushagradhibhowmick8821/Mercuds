#!/usr/bin/env python3
"""
Mercuds Network Monitor - Main Entry Point
A prototype IDS network monitoring system
"""

import argparse
import signal
import sys
import os
from datetime import datetime

from sniffer import PacketSniffer
from analyzer import TrafficAnalyzer
from dashboard import Dashboard


class NetworkMonitor:
    """
    Main orchestrator for the network monitoring system
    """
    
    def __init__(self, interface: str = None, bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        
        # Initialize components
        self.sniffer = PacketSniffer(interface=interface)
        self.analyzer = TrafficAnalyzer()
        self.dashboard = Dashboard()
        
        # Wire up the pipeline
        self.sniffer.register_callback(self._process_packet)
        
        # Stats
        self.start_time = None
        self._running = False
    
    def _process_packet(self, packet_info):
        """Process each captured packet through the analysis pipeline"""
        # Update dashboard with packet
        self.dashboard.add_packet(packet_info)
        
        # Analyze for threats
        alerts = self.analyzer.analyze_packet(packet_info)
        
        # Add any alerts to dashboard
        for alert in alerts:
            self.dashboard.add_alert(alert)
            self._log_alert(alert)
    
    def _log_alert(self, alert):
        """Log alert to file"""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"alerts_{datetime.now().strftime('%Y%m%d')}.log")
        with open(log_file, "a") as f:
            f.write(f"{alert.to_dict()}\n")
    
    def start(self):
        """Start the network monitor"""
        self.start_time = datetime.now()
        self._running = True
        
        print(f"\n🛡️  Starting Mercuds Network Monitor...")
        print(f"   Interface: {self.interface or 'default'}")
        print(f"   Filter: {self.bpf_filter or 'none'}")
        print(f"   Press Ctrl+C to stop\n")
        
        # Start packet capture
        self.sniffer.start(bpf_filter=self.bpf_filter)
        
        # Start dashboard (blocking)
        try:
            self.dashboard.start(get_summary_callback=self.analyzer.get_summary)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Stop all components"""
        self._running = False
        self.sniffer.stop()
        self.dashboard.stop()
        
        # Print final summary
        print("\n\n📊 Final Summary:")
        print("=" * 50)
        
        stats = self.sniffer.get_stats()
        print(f"Total Packets: {stats.get('total_packets', 0)}")
        print(f"Runtime: {stats.get('runtime_seconds', 0):.1f} seconds")
        print(f"Average Rate: {stats.get('packets_per_second', 0):.1f} packets/sec")
        
        summary = self.analyzer.get_summary()
        print(f"\nTotal Alerts: {summary['total_alerts']}")
        print(f"Unique IPs: {summary['unique_ips']}")
        print(f"Connections Tracked: {summary['total_connections']}")
        
        if summary['alerts_by_severity']:
            print("\nAlerts by Severity:")
            for level, count in summary['alerts_by_severity'].items():
                print(f"  {level.upper()}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description="Mercuds Network Monitor - IDS Prototype",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all traffic on default interface
  sudo python main.py
  
  # Monitor specific interface
  sudo python main.py -i en0
  
  # Monitor only HTTP traffic
  sudo python main.py -f "tcp port 80 or tcp port 443"
  
  # Monitor traffic to/from specific host
  sudo python main.py -f "host 192.168.1.100"
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor (e.g., en0, eth0)"
    )
    
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="BPF filter string (e.g., 'tcp port 80')"
    )
    
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces"
    )
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        from scapy.all import get_if_list
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  {iface}")
        return
    
    # Check for root/admin privileges
    if os.geteuid() != 0:
        print("⚠️  Warning: Packet capture typically requires root privileges.")
        print("   Try running with: sudo python main.py")
        print()
    
    # Set up signal handlers
    monitor = NetworkMonitor(
        interface=args.interface,
        bpf_filter=args.filter
    )
    
    def signal_handler(sig, frame):
        print("\n\nReceived interrupt signal, shutting down...")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor.start()


if __name__ == "__main__":
    main()
