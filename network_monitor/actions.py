"""
Actions Module
Perform actions based on detected threats
"""

import subprocess
import os
import json
from datetime import datetime
from typing import Optional


class ActionEngine:
    """
    Execute response actions for detected threats
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Track blocked IPs (in-memory for now)
        self.blocked_ips: set[str] = set()
        self.whitelisted_ips: set[str] = {"127.0.0.1", "::1"}
        
        # Action history
        self.action_history: list[dict] = []
    
    def block_ip(self, ip: str, reason: str = "") -> dict:
        """
        Block an IP address using macOS pf firewall
        Returns result dict with success status
        """
        if ip in self.whitelisted_ips:
            return {"success": False, "error": "IP is whitelisted", "ip": ip}
        
        if ip in self.blocked_ips:
            return {"success": False, "error": "IP already blocked", "ip": ip}
        
        # Add to pf block table (macOS)
        # This requires the pf firewall to be configured with a table
        try:
            # For macOS - add to a pf table called "blocklist"
            result = subprocess.run(
                ["sudo", "pfctl", "-t", "blocklist", "-T", "add", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                self._log_action("BLOCK", ip, reason, success=True)
                return {"success": True, "ip": ip, "message": f"Blocked {ip}"}
            else:
                # Fallback: just track it (pf table might not exist)
                self.blocked_ips.add(ip)
                self._log_action("BLOCK", ip, reason, success=True, note="tracked only - pf not configured")
                return {"success": True, "ip": ip, "message": f"Tracked block for {ip} (configure pf for enforcement)"}
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out", "ip": ip}
        except Exception as e:
            # Still track it even if firewall command fails
            self.blocked_ips.add(ip)
            self._log_action("BLOCK", ip, reason, success=True, note=f"tracked only - {str(e)}")
            return {"success": True, "ip": ip, "message": f"Tracked block for {ip}"}
    
    def unblock_ip(self, ip: str) -> dict:
        """Remove an IP from the block list"""
        if ip not in self.blocked_ips:
            return {"success": False, "error": "IP not in block list", "ip": ip}
        
        try:
            subprocess.run(
                ["sudo", "pfctl", "-t", "blocklist", "-T", "delete", ip],
                capture_output=True,
                timeout=5
            )
        except:
            pass  # Continue even if pf command fails
        
        self.blocked_ips.discard(ip)
        self._log_action("UNBLOCK", ip, "", success=True)
        return {"success": True, "ip": ip, "message": f"Unblocked {ip}"}
    
    def whitelist_ip(self, ip: str) -> dict:
        """Add IP to whitelist (will never be blocked)"""
        self.whitelisted_ips.add(ip)
        
        # Also unblock if currently blocked
        if ip in self.blocked_ips:
            self.unblock_ip(ip)
        
        self._log_action("WHITELIST", ip, "", success=True)
        return {"success": True, "ip": ip, "message": f"Whitelisted {ip}"}
    
    def lookup_ip(self, ip: str) -> dict:
        """
        Get information about an IP address
        Uses local tools (no external API needed)
        """
        info = {
            "ip": ip,
            "blocked": ip in self.blocked_ips,
            "whitelisted": ip in self.whitelisted_ips,
            "reverse_dns": None,
            "route": None
        }
        
        # Reverse DNS lookup
        try:
            result = subprocess.run(
                ["host", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                info["reverse_dns"] = result.stdout.strip()
        except:
            pass
        
        # Check if IP is routable
        try:
            result = subprocess.run(
                ["route", "get", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        info["route"] = line.strip()
                        break
        except:
            pass
        
        return info
    
    def export_alerts(self, alerts: list, filename: str = None) -> dict:
        """Export alerts to JSON file"""
        if not filename:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.log_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump([a.to_dict() if hasattr(a, 'to_dict') else a for a in alerts], f, indent=2)
            return {"success": True, "file": filepath, "count": len(alerts)}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def export_packets(self, packets: list, filename: str = None) -> dict:
        """Export captured packets to JSON"""
        if not filename:
            filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.log_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump([p.to_dict() if hasattr(p, 'to_dict') else p for p in packets], f, indent=2)
            return {"success": True, "file": filepath, "count": len(packets)}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_blocked_ips(self) -> list[str]:
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
    
    def get_whitelisted_ips(self) -> list[str]:
        """Get list of whitelisted IPs"""
        return list(self.whitelisted_ips)
    
    def _log_action(self, action: str, target: str, reason: str, success: bool, note: str = ""):
        """Log an action"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "target": target,
            "reason": reason,
            "success": success,
            "note": note
        }
        self.action_history.append(entry)
        
        # Also write to file
        log_file = os.path.join(self.log_dir, "actions.log")
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    
    def get_action_history(self) -> list[dict]:
        """Get history of actions taken"""
        return self.action_history


def setup_pf_blocklist():
    """
    One-time setup: Configure macOS pf firewall with a blocklist table
    Run this once with sudo to enable IP blocking
    """
    pf_rules = """
# Mercuds IDS blocklist
table <blocklist> persist
block drop quick from <blocklist>
block drop quick to <blocklist>
"""
    
    print("To enable IP blocking on macOS, add these rules to /etc/pf.conf:")
    print("-" * 50)
    print(pf_rules)
    print("-" * 50)
    print("\nThen run: sudo pfctl -f /etc/pf.conf && sudo pfctl -e")
    print("\nNote: This is optional. The monitor will track blocks even without pf.")
