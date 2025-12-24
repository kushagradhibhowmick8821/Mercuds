"""
Threat Intelligence Module
Manages known malicious indicators (IPs, domains, signatures)
Integrates with AbuseIPDB for real-time threat lookups
"""

import json
import os
import requests
from dataclasses import dataclass
from typing import Optional, Set
from datetime import datetime
import hashlib


# AbuseIPDB API Configuration
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseIPDBResult:
    """Result from AbuseIPDB lookup"""
    ip: str
    is_public: bool
    abuse_confidence_score: int  # 0-100
    country_code: str
    isp: str
    domain: str
    total_reports: int
    last_reported: Optional[datetime]
    is_whitelisted: bool
    categories: list[int]
    
    @property
    def is_malicious(self) -> bool:
        """Consider malicious if abuse score >= 25"""
        return self.abuse_confidence_score >= 25
    
    @property
    def threat_level(self) -> str:
        if self.abuse_confidence_score >= 75:
            return "critical"
        elif self.abuse_confidence_score >= 50:
            return "high"
        elif self.abuse_confidence_score >= 25:
            return "medium"
        return "low"
    
    @property
    def category_names(self) -> list[str]:
        """Convert category IDs to names"""
        CATEGORIES = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
            11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
            15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
            18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
            21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
        }
        return [CATEGORIES.get(c, f"Unknown({c})") for c in self.categories]


@dataclass
class ThreatIndicator:
    """A single threat indicator"""
    indicator_type: str  # "ip", "domain", "hash", "port"
    value: str
    threat_type: str     # "malware", "c2", "scanner", "botnet", etc.
    confidence: float    # 0.0 to 1.0
    source: str
    last_updated: datetime
    description: str = ""


class ThreatIntelligence:
    """
    Manages threat intelligence data for lookups
    Integrates with AbuseIPDB for real-time threat intelligence
    """
    
    def __init__(self, data_dir: str = "threat_data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
        # In-memory lookups for speed
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.suspicious_ports: dict[int, str] = {}
        
        # Detailed indicator storage
        self.indicators: dict[str, ThreatIndicator] = {}
        
        # AbuseIPDB API key (get free key at https://www.abuseipdb.com/account/api)
        self.abuseipdb_api_key: Optional[str] = None
        self._load_api_key()
        
        # Cache for API lookups (avoid hitting rate limits)
        self._abuseipdb_cache: dict[str, tuple[AbuseIPDBResult, datetime]] = {}
        self._cache_ttl_seconds = 3600  # 1 hour cache
        
        # Load default threat data
        self._load_defaults()
    
    def _load_api_key(self):
        """Load AbuseIPDB API key from environment or config file"""
        # Try environment variable first
        self.abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
        
        # Try config file
        if not self.abuseipdb_api_key:
            config_file = os.path.join(self.data_dir, "api_keys.json")
            if os.path.exists(config_file):
                try:
                    with open(config_file, "r") as f:
                        config = json.load(f)
                        self.abuseipdb_api_key = config.get("abuseipdb")
                except:
                    pass
    
    def set_abuseipdb_key(self, api_key: str):
        """Set and save AbuseIPDB API key"""
        self.abuseipdb_api_key = api_key
        
        # Save to config file
        config_file = os.path.join(self.data_dir, "api_keys.json")
        config = {}
        if os.path.exists(config_file):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
            except:
                pass
        
        config["abuseipdb"] = api_key
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)
    
    def check_ip_abuseipdb(self, ip: str, max_age_days: int = 90) -> Optional[AbuseIPDBResult]:
        """
        Check an IP against AbuseIPDB
        Returns AbuseIPDBResult or None if lookup fails
        
        Free tier: 1000 checks/day
        """
        if not self.abuseipdb_api_key:
            return None
        
        # Check cache first
        if ip in self._abuseipdb_cache:
            result, cached_at = self._abuseipdb_cache[ip]
            age = (datetime.now() - cached_at).total_seconds()
            if age < self._cache_ttl_seconds:
                return result
        
        try:
            headers = {
                "Key": self.abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": ""
            }
            
            response = requests.get(
                f"{ABUSEIPDB_API_URL}/check",
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                last_reported = None
                if data.get("lastReportedAt"):
                    try:
                        last_reported = datetime.fromisoformat(
                            data["lastReportedAt"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                result = AbuseIPDBResult(
                    ip=data.get("ipAddress", ip),
                    is_public=data.get("isPublic", True),
                    abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                    country_code=data.get("countryCode", ""),
                    isp=data.get("isp", ""),
                    domain=data.get("domain", ""),
                    total_reports=data.get("totalReports", 0),
                    last_reported=last_reported,
                    is_whitelisted=data.get("isWhitelisted", False),
                    categories=data.get("reports", [{}])[0].get("categories", []) if data.get("reports") else []
                )
                
                # Cache the result
                self._abuseipdb_cache[ip] = (result, datetime.now())
                
                # If malicious, add to our local database
                if result.is_malicious:
                    self.add_indicator(ThreatIndicator(
                        indicator_type="ip",
                        value=ip,
                        threat_type=result.category_names[0] if result.category_names else "malicious",
                        confidence=result.abuse_confidence_score / 100.0,
                        source="abuseipdb",
                        last_updated=datetime.now(),
                        description=f"AbuseIPDB: {result.total_reports} reports, score {result.abuse_confidence_score}%"
                    ))
                
                return result
            
            elif response.status_code == 429:
                # Rate limited
                return None
            
        except requests.RequestException:
            pass
        
        return None
    
    def bulk_check_abuseipdb(self, ips: list[str]) -> dict[str, AbuseIPDBResult]:
        """Check multiple IPs against AbuseIPDB (uses blacklist endpoint)"""
        results = {}
        
        # For now, check individually (bulk requires paid plan)
        for ip in ips[:10]:  # Limit to avoid rate limits
            result = self.check_ip_abuseipdb(ip)
            if result:
                results[ip] = result
        
        return results
    
    def _load_defaults(self):
        """Load default threat indicators"""
        
        # Known malicious/suspicious ports
        self.suspicious_ports = {
            4444: "Metasploit default listener",
            5555: "Android ADB (often exploited)",
            6666: "IRC backdoor",
            6667: "IRC (common C2 channel)",
            1337: "Common backdoor port",
            31337: "Back Orifice trojan",
            12345: "NetBus trojan",
            27374: "SubSeven trojan",
            3127: "MyDoom backdoor",
            6697: "IRC over TLS (C2)",
            9001: "Tor default",
            9050: "Tor SOCKS proxy",
        }
        
        # Sample malicious IPs (for demo - in production, load from threat feeds)
        self._add_sample_threat_ips()
        
        # Load any custom data files
        self._load_custom_data()
    
    def _add_sample_threat_ips(self):
        """Add sample threat IPs for demonstration"""
        sample_threats = [
            # These are example/documentation IPs - NOT real threats
            ("192.0.2.1", "scanner", "Example scanner IP"),
            ("198.51.100.1", "c2", "Example C2 server"),
            ("203.0.113.1", "botnet", "Example botnet node"),
        ]
        
        for ip, threat_type, desc in sample_threats:
            self.add_indicator(ThreatIndicator(
                indicator_type="ip",
                value=ip,
                threat_type=threat_type,
                confidence=0.9,
                source="sample_data",
                last_updated=datetime.now(),
                description=desc
            ))
    
    def _load_custom_data(self):
        """Load custom threat data from files"""
        # Load malicious IPs
        ip_file = os.path.join(self.data_dir, "malicious_ips.txt")
        if os.path.exists(ip_file):
            with open(ip_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.malicious_ips.add(line)
        
        # Load malicious domains
        domain_file = os.path.join(self.data_dir, "malicious_domains.txt")
        if os.path.exists(domain_file):
            with open(domain_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.malicious_domains.add(line.lower())
    
    def add_indicator(self, indicator: ThreatIndicator):
        """Add a threat indicator"""
        key = f"{indicator.indicator_type}:{indicator.value}"
        self.indicators[key] = indicator
        
        if indicator.indicator_type == "ip":
            self.malicious_ips.add(indicator.value)
        elif indicator.indicator_type == "domain":
            self.malicious_domains.add(indicator.value.lower())
    
    def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Check if an IP is known malicious"""
        if ip in self.malicious_ips:
            key = f"ip:{ip}"
            return self.indicators.get(key)
        return None
    
    def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check if a domain is known malicious"""
        domain = domain.lower()
        if domain in self.malicious_domains:
            key = f"domain:{domain}"
            return self.indicators.get(key)
        return None
    
    def check_port(self, port: int) -> Optional[str]:
        """Check if a port is suspicious"""
        return self.suspicious_ports.get(port)
    
    def save_indicators(self):
        """Save current indicators to file"""
        output_file = os.path.join(self.data_dir, "indicators.json")
        
        data = []
        for indicator in self.indicators.values():
            data.append({
                "indicator_type": indicator.indicator_type,
                "value": indicator.value,
                "threat_type": indicator.threat_type,
                "confidence": indicator.confidence,
                "source": indicator.source,
                "last_updated": indicator.last_updated.isoformat(),
                "description": indicator.description
            })
        
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def load_indicators(self):
        """Load indicators from file"""
        input_file = os.path.join(self.data_dir, "indicators.json")
        
        if not os.path.exists(input_file):
            return
        
        with open(input_file, "r") as f:
            data = json.load(f)
        
        for item in data:
            indicator = ThreatIndicator(
                indicator_type=item["indicator_type"],
                value=item["value"],
                threat_type=item["threat_type"],
                confidence=item["confidence"],
                source=item["source"],
                last_updated=datetime.fromisoformat(item["last_updated"]),
                description=item.get("description", "")
            )
            self.add_indicator(indicator)
    
    def get_stats(self) -> dict:
        """Get threat intelligence statistics"""
        return {
            "total_indicators": len(self.indicators),
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
            "suspicious_ports": len(self.suspicious_ports)
        }
