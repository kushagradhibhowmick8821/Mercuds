"""
GeoIP Module
IP Geolocation using ip-api.com (free, no API key needed)
"""

import requests
from functools import lru_cache
from typing import Optional, Dict
from dataclasses import dataclass
import ipaddress


@dataclass
class GeoLocation:
    """Geographic location data for an IP"""
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    lat: float
    lon: float
    isp: str
    org: str
    as_number: str
    is_private: bool = False
    
    def short(self) -> str:
        """Short format: City, Country"""
        if self.is_private:
            return "Private/Local"
        if self.city and self.country_code:
            return f"{self.city}, {self.country_code}"
        if self.country:
            return self.country
        return "Unknown"
    
    def full(self) -> str:
        """Full format with all details"""
        if self.is_private:
            return f"{self.ip} - Private/Local Network"
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        location = ", ".join(parts) if parts else "Unknown"
        return f"{self.ip} - {location} ({self.isp})"


class GeoIPLookup:
    """
    IP Geolocation service using ip-api.com
    Free tier: 45 requests/minute
    """
    
    API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fc00::/7"),  # IPv6 private
        ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ]
    
    def __init__(self):
        self._cache: Dict[str, GeoLocation] = {}
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.PRIVATE_RANGES:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            return False
    
    @lru_cache(maxsize=1000)
    def lookup(self, ip: str) -> Optional[GeoLocation]:
        """
        Look up geographic location for an IP address
        Results are cached to minimize API calls
        """
        # Handle private IPs locally
        if self.is_private_ip(ip):
            return GeoLocation(
                ip=ip,
                country="Local",
                country_code="--",
                region="",
                city="Private Network",
                lat=0.0,
                lon=0.0,
                isp="Local",
                org="Private",
                as_number="",
                is_private=True
            )
        
        try:
            response = requests.get(
                self.API_URL.format(ip=ip),
                timeout=2
            )
            data = response.json()
            
            if data.get("status") == "success":
                return GeoLocation(
                    ip=ip,
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "??"),
                    region=data.get("regionName", ""),
                    city=data.get("city", ""),
                    lat=data.get("lat", 0.0),
                    lon=data.get("lon", 0.0),
                    isp=data.get("isp", "Unknown"),
                    org=data.get("org", ""),
                    as_number=data.get("as", ""),
                    is_private=False
                )
            else:
                return None
                
        except Exception:
            return None
    
    def lookup_batch(self, ips: list) -> Dict[str, GeoLocation]:
        """Look up multiple IPs (uses cache efficiently)"""
        results = {}
        for ip in ips:
            result = self.lookup(ip)
            if result:
                results[ip] = result
        return results
    
    def get_country_flag(self, country_code: str) -> str:
        """Convert country code to flag emoji"""
        if not country_code or country_code == "--" or len(country_code) != 2:
            return "🏠"  # Local/private
        
        # Convert country code to regional indicator symbols
        try:
            flag = "".join(chr(ord(c) + 127397) for c in country_code.upper())
            return flag
        except:
            return "🌍"


# Global instance for easy access
geoip = GeoIPLookup()
