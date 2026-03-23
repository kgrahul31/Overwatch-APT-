import base64
import re
import urllib.parse

def decode_base64_payloads(payload: str) -> str:
    """
    Looks for Base64 encoded strings in a payload (like a PowerShell command)
    and attempts to decode them. Returns a summary of decoded content.
    """
    # Regex to find potential Base64 strings (length > 20, ending in = or normal char)
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    matches = b64_pattern.findall(payload)
    
    decoded_results = []
    
    for match in set(matches):
        try:
            # Add padding if necessary
            padded_match = match + '=' * (-len(match) % 4)
            decoded_bytes = base64.b64decode(padded_match)
            
            # Try decoding as UTF-16LE (common in PowerShell -enc)
            try:
                decoded_str = decoded_bytes.decode('utf-16le')
            except UnicodeDecodeError:
                # Fallback to UTF-8
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
            if len(decoded_str.strip()) > 5:  # ensure it actually decoded meaningfully
                decoded_results.append(decoded_str)
        except Exception:
            pass

    if decoded_results:
        return "\n\n--- Decoded Base64 Payload ---\n" + "\n\n".join(decoded_results)
    
    return ""

def decode_url_payloads(payload: str) -> str:
    """Decodes URL encoded payloads (e.g. %20)."""
    if '%' in payload:
        decoded = urllib.parse.unquote(payload)
        if decoded != payload:
            return f"\n\n--- URL Decoded Payload ---\n{decoded}"
    return ""

def analyze_payload_obfuscation(payload: str) -> str:
    """Runs multiple deobfuscation techniques on a raw string/payload."""
    if not payload:
        return ""
        
    result = ""
    # Check for Base64
    b64_res = decode_base64_payloads(payload)
    if b64_res:
        result += b64_res
        
    # Check for URL encoding
    url_res = decode_url_payloads(payload)
    if url_res:
        result += url_res
        
    return result
