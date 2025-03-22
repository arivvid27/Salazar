import requests
import json
from app.config import Config

def check_safe_browsing(url):
    """
    Check a URL against Google Safe Browsing API
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary with threat information if found, empty if safe
    """
    if not Config.SAFE_BROWSING_API_KEY:
        return {
            "success": False,
            "error": "Safe Browsing API key not configured",
            "threats": []
        }
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {
            "clientId": Config.SAFE_BROWSING_CLIENT_ID,
            "clientVersion": Config.SAFE_BROWSING_CLIENT_VERSION
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload)
        result = response.json()
        
        if "matches" in result:
            threats = []
            for match in result["matches"]:
                threats.append({
                    "type": match.get("threatType", "UNKNOWN"),
                    "platform": match.get("platformType", "UNKNOWN"),
                    "threat_entry_type": match.get("threatEntryType", "UNKNOWN")
                })
            
            return {
                "success": True,
                "threats": threats,
                "recommendations": [
                    "Leave this website immediately",
                    "Do not download any files or enter any information",
                    "Consider running a malware scan on your device"
                ]
            }
        
        return {
            "success": True,
            "threats": []
        }
    
    except Exception as e:
        print(f"Error calling Safe Browsing API: {e}")
        return {
            "success": False,
            "error": str(e),
            "threats": []
        }