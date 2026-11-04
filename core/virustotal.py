"""
ThreatLens - VirusTotal Integration
Hash-based file reputation lookup via VirusTotal API v3.
"""

import json
import time
from pathlib import Path


# VirusTotal API v3 endpoint
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def load_api_key():
    """
    Load the VirusTotal API key from config.local.json, config.json, or environment variables.
    
    Returns:
        str or None: The API key, or None if not configured.
    """
    # Check config.local.json first (git-ignored), then config.json
    root_dir = Path(__file__).parent.parent
    for fname in ["config.local.json", "config.json"]:
        cpath = root_dir / fname
        if cpath.exists():
            try:
                with open(cpath, "r", encoding="utf-8") as f:
                    config = json.load(f)
                key = config.get("virustotal_api_key", "").strip()
                enabled = config.get("vt_enabled", True)
                if key and enabled and not key.startswith("YOUR_"):
                    return key
            except Exception:
                pass

    import os
    env_key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    return None


def test_api_key(api_key=None):
    """
    Test connectivity and validity of the VirusTotal API key against VirusTotal API v3.
    
    Returns:
        dict: Test results with status, message, and account metadata.
    """
    if not api_key:
        api_key = load_api_key()

    if not api_key:
        return {"success": False, "status": "missing", "message": "No VirusTotal API key configured"}

    try:
        import requests
    except ImportError:
        return {"success": False, "status": "error", "message": "requests library not installed"}

    headers = {"x-apikey": api_key}
    try:
        response = requests.get("https://www.virustotal.com/api/v3/users/current", headers=headers, timeout=(10, 20))
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            user_status = data.get("status", "active")
            masked = api_key[:4] + "*" * max(0, len(api_key) - 8) + api_key[-4:] if len(api_key) > 8 else "***"
            return {
                "success": True,
                "status": user_status,
                "message": f"Connected successfully (Account status: {user_status})",
                "api_key_masked": masked,
            }
        elif response.status_code == 401:
            return {"success": False, "status": "unauthorized", "message": "Invalid VirusTotal API key (HTTP 401)"}
        elif response.status_code == 429:
            return {"success": False, "status": "rate_limited", "message": "API rate limit reached (HTTP 429). Wait 60s."}
        else:
            return {"success": False, "status": "http_error", "message": f"VirusTotal returned HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"success": False, "status": "timeout", "message": "Connection to VirusTotal timed out"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "status": "network_error", "message": "Cannot reach VirusTotal (check internet connection)"}
    except Exception as e:
        return {"success": False, "status": "error", "message": f"VirusTotal connection test failed: {str(e)}"}


def lookup_hash(file_hash, api_key=None):
    """
    Look up a file hash on VirusTotal.
    
    Args:
        file_hash: SHA256 hash of the file.
        api_key: VT API key (if None, loads from config).
        
    Returns:
        dict: VT results with detection stats, or error info.
    """
    if not api_key:
        api_key = load_api_key()
    
    if not api_key:
        return {
            "status": "skipped",
            "reason": "No VirusTotal API key configured",
            "hash": file_hash,
            "detection_count": 0,
            "total_engines": 0,
            "detection_rate": "0/0",
            "detection_ratio": 0.0,
            "severity": "NONE",
            "threat_label": "",
            "detections": [],
            "tags": [],
            "permalink": "",
        }
    
    try:
        import requests
    except ImportError:
        return {
            "status": "error",
            "reason": "requests library not installed (pip install requests)",
            "hash": file_hash,
            "detection_count": 0,
            "total_engines": 0,
            "detection_rate": "0/0",
            "detection_ratio": 0.0,
            "severity": "ERROR",
            "threat_label": "",
            "detections": [],
            "tags": [],
            "permalink": "",
        }
    
    url = VT_API_URL.format(hash=file_hash)
    headers = {"x-apikey": api_key}
    
    try:
        response = None
        for attempt in range(2):
            try:
                response = requests.get(url, headers=headers, timeout=(8, 25))
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt == 1:
                    raise
                time.sleep(1)
        
        if response.status_code == 200:
            return _parse_vt_response(response.json())
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "reason": "File hash not found in VirusTotal database (New / Unseen Sample)",
                "hash": file_hash,
                "detection_count": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "undetected_count": 0,
                "harmless_count": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "detection_ratio": 0.0,
                "severity": "CLEAN",
                "threat_label": "",
                "detections": [],
                "tags": [],
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        elif response.status_code == 401:
            return {
                "status": "error",
                "reason": "Invalid VirusTotal API key (HTTP 401)",
                "hash": file_hash,
                "detection_count": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "detection_ratio": 0.0,
                "severity": "ERROR",
                "threat_label": "",
                "detections": [],
                "tags": [],
                "permalink": "",
            }
        elif response.status_code == 429:
            return {
                "status": "error",
                "reason": "VirusTotal API rate limit exceeded. Wait 60 seconds.",
                "hash": file_hash,
                "detection_count": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "detection_ratio": 0.0,
                "severity": "ERROR",
                "threat_label": "",
                "detections": [],
                "tags": [],
                "permalink": "",
            }
        else:
            return {
                "status": "error",
                "reason": f"VT API returned HTTP {response.status_code}",
                "hash": file_hash,
                "detection_count": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "detection_ratio": 0.0,
                "severity": "ERROR",
                "threat_label": "",
                "detections": [],
                "tags": [],
                "permalink": "",
            }
            
    except requests.exceptions.Timeout:
        return {
            "status": "error",
            "reason": "VirusTotal API request timed out (30s)",
            "hash": file_hash,
            "detection_count": 0,
            "total_engines": 0,
            "detection_rate": "0/0",
            "detection_ratio": 0.0,
            "severity": "ERROR",
            "threat_label": "",
            "detections": [],
            "tags": [],
            "permalink": "",
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "error",
            "reason": "Cannot connect to VirusTotal (check internet connection)",
            "hash": file_hash,
            "detection_count": 0,
            "total_engines": 0,
            "detection_rate": "0/0",
            "detection_ratio": 0.0,
            "severity": "ERROR",
            "threat_label": "",
            "detections": [],
            "tags": [],
            "permalink": "",
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"VirusTotal lookup failed: {str(e)}",
            "hash": file_hash,
            "detection_count": 0,
            "total_engines": 0,
            "detection_rate": "0/0",
            "detection_ratio": 0.0,
            "severity": "ERROR",
            "threat_label": "",
            "detections": [],
            "tags": [],
            "permalink": "",
        }


def _parse_vt_response(data):
    """
    Parse the VirusTotal API v3 response into a clean result dict.
    
    Args:
        data: Raw JSON response from VT API.
        
    Returns:
        dict: Parsed results.
    """
    try:
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless
        
        # Collect which engines detected it
        detections = []
        for engine_name, engine_result in results.items():
            if engine_result.get("category") in ("malicious", "suspicious"):
                detections.append({
                    "engine": engine_name,
                    "result": engine_result.get("result", "Unknown"),
                    "category": engine_result.get("category", ""),
                })
        
        # Sort detections alphabetically by engine name
        detections.sort(key=lambda x: x["engine"])
        
        # Determine severity based on detection ratio
        detection_count = malicious + suspicious
        if total > 0:
            ratio = detection_count / total
        else:
            ratio = 0
            
        if ratio >= 0.5:
            vt_severity = "CRITICAL"
        elif ratio >= 0.25:
            vt_severity = "HIGH"
        elif ratio >= 0.1:
            vt_severity = "MEDIUM"
        elif detection_count > 0:
            vt_severity = "LOW"
        else:
            vt_severity = "CLEAN"
        
        # File metadata from VT
        file_info = {
            "type_description": attributes.get("type_description", "Unknown"),
            "type_tag": attributes.get("type_tag", ""),
            "size": attributes.get("size", 0),
            "first_seen": attributes.get("first_submission_date", ""),
            "last_seen": attributes.get("last_analysis_date", ""),
            "times_submitted": attributes.get("times_submitted", 0),
            "reputation": attributes.get("reputation", 0),
        }
        
        # Popular threat label
        popular = attributes.get("popular_threat_classification", {})
        threat_label = ""
        if popular:
            suggested = popular.get("suggested_threat_label", "")
            if suggested:
                threat_label = suggested
        
        # Tags
        tags = attributes.get("tags", [])
        
        sha256 = attributes.get("sha256", "")
        
        return {
            "status": "found",
            "hash": sha256,
            "detection_count": detection_count,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "undetected_count": undetected,
            "harmless_count": harmless,
            "total_engines": total,
            "detection_rate": f"{detection_count}/{total}",
            "detection_ratio": round(ratio * 100, 1),
            "severity": vt_severity,
            "threat_label": threat_label,
            "detections": detections[:30],  # Top 30 detections
            "file_info": file_info,
            "tags": tags[:10],
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
        
    except Exception as e:
        return {"status": "error", "reason": f"Error parsing VT response: {str(e)}"}


def get_vt_score_contribution(vt_result):
    """
    Calculate threat score contribution from VirusTotal results.
    
    Args:
        vt_result: dict from lookup_hash().
        
    Returns:
        int: Score contribution (0-35).
    """
    if vt_result.get("status") != "found":
        return 0
    
    ratio = vt_result.get("detection_ratio", 0)
    
    if ratio >= 50:
        return 35
    elif ratio >= 25:
        return 25
    elif ratio >= 10:
        return 15
    elif ratio > 0:
        return 8
    return 0


def lookup_ip(ip_address, api_key=None):
    """
    Look up an IP address on VirusTotal v3 IP Intelligence.
    
    Args:
        ip_address: IPv4 address string.
        api_key: Optional VT API key.
        
    Returns:
        dict: Parsed IP intelligence (country, as_owner, asn, malicious_count, total_engines, reputation, tags, permalink).
    """
    if not api_key:
        api_key = load_api_key()
    
    if not api_key:
        return {
            "status": "skipped",
            "ip": ip_address,
            "reason": "No VirusTotal API key configured",
            "malicious_count": 0,
            "total_engines": 0,
            "country": "Unknown",
            "as_owner": "Unknown",
            "asn": 0,
            "network": "",
            "tags": [],
            "reputation": 0,
            "severity": "UNKNOWN",
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_address}",
        }
        
    try:
        import requests
    except ImportError:
        return {"status": "error", "ip": ip_address, "reason": "requests library missing"}
        
    url = VT_IP_URL.format(ip=ip_address)
    headers = {"x-apikey": api_key}
    
    try:
        response = None
        for attempt in range(2):
            try:
                response = requests.get(url, headers=headers, timeout=(8, 20))
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt == 1:
                    raise
                time.sleep(1)
                
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + undetected + harmless
            
            tags = data.get("tags", [])
            as_owner = data.get("as_owner", "Unknown")
            country = data.get("country", "Unknown")
            asn = data.get("asn", 0)
            network = data.get("network", "")
            reputation = data.get("reputation", 0)
            
            severity = "CLEAN"
            if malicious >= 5:
                severity = "CRITICAL"
            elif malicious >= 2:
                severity = "HIGH"
            elif malicious >= 1 or suspicious >= 2:
                severity = "MEDIUM"
                
            return {
                "status": "found",
                "ip": ip_address,
                "country": country,
                "as_owner": as_owner,
                "asn": asn,
                "network": network,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_rate": f"{malicious}/{total}",
                "reputation": reputation,
                "tags": tags[:8],
                "severity": severity,
                "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            }
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "ip": ip_address,
                "country": "Unknown",
                "as_owner": "Unknown",
                "asn": 0,
                "malicious_count": 0,
                "total_engines": 0,
                "detection_rate": "0/0",
                "reputation": 0,
                "tags": [],
                "severity": "CLEAN",
                "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            }
        elif response.status_code == 429:
            return {"status": "error", "ip": ip_address, "reason": "VirusTotal API rate limit reached"}
        else:
            return {"status": "error", "ip": ip_address, "reason": f"HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"status": "error", "ip": ip_address, "reason": "Query timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "ip": ip_address, "reason": "Network connection error"}
    except Exception as e:
        return {"status": "error", "ip": ip_address, "reason": str(e)}


def get_ip_score_contribution(ip_intel):
    """
    Calculate threat score penalty for malicious C2 IP infrastructure.
    
    Args:
        ip_intel: dict from lookup_ip().
        
    Returns:
        int: Score penalty (0-30).
    """
    if not ip_intel or ip_intel.get("status") != "found":
        return 0
        
    malicious = ip_intel.get("malicious_count", 0)
    tags = [t.lower() for t in ip_intel.get("tags", [])]
    
    score = 0
    if malicious >= 5:
        score += 25
    elif malicious >= 2:
        score += 15
    elif malicious >= 1:
        score += 8
        
    if "c2" in tags or "botnet" in tags:
        score += 10
    if "tor" in tags:
        score += 5
        
    return min(30, score)
