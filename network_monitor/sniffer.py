"""
Packet Sniffer Module
Captures and parses network packets in real-time
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional
from collections import defaultdict
import threading
import queue


@dataclass
class PacketInfo:
    """Structured representation of a captured packet"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    flags: str = ""
    payload_preview: str = ""
    raw_packet: object = field(repr=False, default=None)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "flags": self.flags,
            "payload_preview": self.payload_preview
        }


class PacketSniffer:
    """
    Real-time packet capture and parsing engine
    """
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.callbacks: list[Callable] = []  # Callbacks receive (PacketInfo, raw_packet)
        self.is_running = False
        self._sniffer_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = defaultdict(int)
        self.start_time: Optional[datetime] = None
    
    def register_callback(self, callback: Callable):
        """Register a callback function to process each packet.
        Callback receives (packet_info: PacketInfo, raw_packet) as arguments."""
        self.callbacks.append(callback)
    
    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse raw packet into structured PacketInfo"""
        try:
            if not packet.haslayer(IP):
                # Handle ARP separately
                if packet.haslayer(ARP):
                    arp = packet[ARP]
                    return PacketInfo(
                        timestamp=datetime.now(),
                        src_ip=arp.psrc,
                        dst_ip=arp.pdst,
                        src_port=None,
                        dst_port=None,
                        protocol="ARP",
                        length=len(packet),
                        flags=f"op={arp.op}",
                        raw_packet=packet
                    )
                return None
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "OTHER"
            src_port = None
            dst_port = None
            flags = ""
            payload_preview = ""
            
            # Determine protocol and extract ports
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = str(tcp.flags)
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                
                # Check for DNS
                if packet.haslayer(DNS):
                    protocol = "DNS"
                    
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                icmp = packet[ICMP]
                flags = f"type={icmp.type}"
            
            # Extract payload preview (first 50 bytes)
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                try:
                    payload_preview = raw_data[:50].decode('utf-8', errors='replace')
                except:
                    payload_preview = raw_data[:50].hex()
            
            return PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(packet),
                flags=flags,
                payload_preview=payload_preview,
                raw_packet=packet
            )
            
        except Exception as e:
            self.stats["parse_errors"] += 1
            return None
    
    def _packet_handler(self, packet):
        """Handle each captured packet"""
        packet_info = self._parse_packet(packet)
        if packet_info:
            self.stats["total_packets"] += 1
            self.stats[f"protocol_{packet_info.protocol}"] += 1
            
            # Add to queue for async processing
            self.packet_queue.put(packet_info)
            
            # Call registered callbacks with both PacketInfo and raw packet
            for callback in self.callbacks:
                try:
                    callback(packet_info, packet)
                except TypeError:
                    # Fallback for old-style callbacks that only accept 1 arg
                    try:
                        callback(packet_info)
                    except Exception:
                        self.stats["callback_errors"] += 1
                except Exception as e:
                    self.stats["callback_errors"] += 1
    
    def start(self, packet_count: int = 0, bpf_filter: str = ""):
        """
        Start capturing packets
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            bpf_filter: Berkeley Packet Filter string (e.g., "tcp port 80")
        """
        self.is_running = True
        self.start_time = datetime.now()
        
        def _sniff_thread():
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=packet_count if packet_count > 0 else 0,
                filter=bpf_filter if bpf_filter else None,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        
        self._sniffer_thread = threading.Thread(target=_sniff_thread, daemon=True)
        self._sniffer_thread.start()
    
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
    
    def get_stats(self) -> dict:
        """Get capture statistics"""
        runtime = 0
        if self.start_time:
            runtime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "runtime_seconds": runtime,
            "packets_per_second": self.stats["total_packets"] / runtime if runtime > 0 else 0,
            **dict(self.stats)
        }
