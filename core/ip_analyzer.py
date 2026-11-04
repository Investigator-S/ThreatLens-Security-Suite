"""
ThreatLens - IP & C2 Infrastructure Intelligence Analyzer
Performs deep infrastructure attribution, reverse DNS, GeoIP, and VirusTotal reputation on extracted IPs.
"""

import socket
import ipaddress
from core.virustotal import lookup_ip, get_ip_score_contribution


def is_public_ipv4(ip_str: str) -> bool:
    """Check if an IPv4 address is globally routable and public."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except (ipaddress.AddressValueError, ValueError):
        return False


def resolve_reverse_dns(ip_str: str) -> str:
    """Resolve PTR record / Reverse DNS for an IP address."""
    try:
        socket.setdefaulttimeout(3.0)
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return "No PTR record"


def analyze_extracted_ips(network_findings: list) -> list:
    """
    Analyze all IPv4 indicators extracted from binary.
    
    Args:
        network_findings: list of findings from NetworkExtractor.
        
    Returns:
        list of enriched IP intelligence dicts.
    """
    analyzed_ips = []
    seen_ips = set()

    for item in network_findings:
        if item.get("type") == "IPv4":
            ip = item.get("value")
            port = item.get("port")

            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Only analyze public external IPs
            if not is_public_ipv4(ip):
                continue

            # Query VirusTotal IP Intelligence
            vt_ip_intel = lookup_ip(ip)

            # Reverse DNS
            rdns = resolve_reverse_dns(ip)

            # Known RAT / C2 port flags
            port_tag = ""
            if port:
                rat_ports = {
                    4444: "Metasploit Default",
                    1337: "Elite RAT",
                    31337: "Back Orifice",
                    5555: "Android Debug Bridge / Botnet",
                    8080: "HTTP Proxy / Web Shell",
                    8443: "HTTPS Web Shell",
                    6666: "IRC Botnet",
                    7777: "RAT Listener",
                    8888: "C2 Gate Listener",
                }
                port_tag = rat_ports.get(port, "")

            entry = {
                "ip": ip,
                "port": port,
                "port_tag": port_tag,
                "reverse_dns": rdns,
                "country": vt_ip_intel.get("country", "Unknown"),
                "as_owner": vt_ip_intel.get("as_owner", "Unknown"),
                "asn": vt_ip_intel.get("asn", 0),
                "malicious_count": vt_ip_intel.get("malicious_count", 0),
                "total_engines": vt_ip_intel.get("total_engines", 0),
                "detection_rate": vt_ip_intel.get("detection_rate", "0/0"),
                "reputation": vt_ip_intel.get("reputation", 0),
                "tags": vt_ip_intel.get("tags", []),
                "severity": vt_ip_intel.get("severity", "CLEAN"),
                "permalink": vt_ip_intel.get("permalink", ""),
                "score_contribution": get_ip_score_contribution(vt_ip_intel),
            }
            analyzed_ips.append(entry)

    # Sort by malicious count descending
    analyzed_ips.sort(key=lambda x: x["malicious_count"], reverse=True)
    return analyzed_ips
