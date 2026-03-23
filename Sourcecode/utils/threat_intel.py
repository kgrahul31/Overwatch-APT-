import re
import requests

def extract_iocs(log_data):
    """
    Extract possible Indicators of Compromise (IOCs) from the raw log data string.
    """
    iocs = {
        'ips': set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_data)),
        'hashes': set(re.findall(r'\b[A-Fa-f0-9]{64}\b', log_data))  # SHA-256
    }
    
    # Filter out common local/loopback IPs
    local_ips = {'127.0.0.1', '0.0.0.0', '255.255.255.255'}
    iocs['ips'] = {ip for ip in iocs['ips'] if not ip.startswith(('10.', '192.168.')) and ip not in local_ips}
    
    return iocs

def query_virustotal(api_key, ioc, ioc_type="ip-address"):
    """
    Query the VirusTotal v3 API for a specific IP or MAC/Hash.
    ioc_type can be 'ip_addresses' or 'files'
    """
    if not api_key:
        return {"error": "API Key missing", "status": "unscanned"}
        
    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return {"malicious": True, "score": malicious, "total": sum(stats.values())}
            return {"malicious": False, "score": 0, "total": sum(stats.values())}
        else:
            return {"error": f"HTTP {response.status_code}", "status": "error"}
    except Exception as e:
        return {"error": str(e), "status": "error"}

def analyze_iocs(api_key, log_data):
    """
    Extracts all IOCs from the text and queries VT. Returns a summary dictionary.
    """
    iocs = extract_iocs(log_data)
    results = []
    
    for ip in list(iocs['ips'])[:5]:  # Limit to 5 checks to avoid rate limits
        vt_res = query_virustotal(api_key, ip, "ip_addresses")
        results.append({"type": "IP", "value": ip, "vt_result": vt_res})
        
    for hash_val in list(iocs['hashes'])[:5]:
        vt_res = query_virustotal(api_key, hash_val, "files")
        results.append({"type": "SHA256", "value": hash_val, "vt_result": vt_res})
        
    return results
