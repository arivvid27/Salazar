from datetime import datetime
import json
import os
import uuid

class ScanResult:
    def __init__(self, target_url, scan_type="full"):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.scan_type = scan_type
        self.start_time = datetime.now()
        self.end_time = None
        self.duration = None
        self.status = "pending"
        self.results = {
            "xss": {},
            "csrf": {},
            "urls_scanned": [],
            "overview": {
                "risk_level": "Unknown",
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
    
    def complete_scan(self):
        """Mark the scan as complete and calculate duration"""
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()
        self.status = "completed"
        
        # Calculate overview stats
        total_vulns = 0
        risk_levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        # Count XSS vulnerabilities
        for url, xss_result in self.results.get("xss", {}).items():
            if isinstance(xss_result, dict) and "vulnerabilities" in xss_result:
                vuln_count = len(xss_result.get("vulnerabilities", []))
                total_vulns += vuln_count
                
                risk_level = xss_result.get("risk_level", "Low")
                if risk_level == "Critical":
                    risk_levels["Critical"] += vuln_count
                elif risk_level == "High":
                    risk_levels["High"] += vuln_count
                elif risk_level == "Medium":
                    risk_levels["Medium"] += vuln_count
                else:
                    risk_levels["Low"] += vuln_count
        
        # Count CSRF vulnerabilities
        for url, csrf_result in self.results.get("csrf", {}).items():
            if isinstance(csrf_result, dict) and "vulnerabilities" in csrf_result:
                vuln_count = len(csrf_result.get("vulnerabilities", []))
                total_vulns += vuln_count
                
                risk_level = csrf_result.get("risk_level", "Low")
                if risk_level == "Critical":
                    risk_levels["Critical"] += vuln_count
                elif risk_level == "High":
                    risk_levels["High"] += vuln_count
                elif risk_level == "Medium":
                    risk_levels["Medium"] += vuln_count
                else:
                    risk_levels["Low"] += vuln_count
        
        # Determine overall risk level
        overall_risk = "Low"
        if risk_levels["Critical"] > 0:
            overall_risk = "Critical"
        elif risk_levels["High"] > 0:
            overall_risk = "High"
        elif risk_levels["Medium"] > 0:
            overall_risk = "Medium"
        
        # Update overview
        self.results["overview"] = {
            "risk_level": overall_risk,
            "total_vulnerabilities": total_vulns,
            "critical": risk_levels["Critical"],
            "high": risk_levels["High"],
            "medium": risk_levels["Medium"],
            "low": risk_levels["Low"]
        }
    
    def add_xss_result(self, url, result):
        """Add XSS scanning result for a URL"""
        if "xss" not in self.results:
            self.results["xss"] = {}
        self.results["xss"][url] = result
    
    def add_csrf_result(self, url, result):
        """Add CSRF scanning result for a URL"""
        if "csrf" not in self.results:
            self.results["csrf"] = {}
        self.results["csrf"][url] = result
    
    def add_scanned_url(self, url):
        """Add a URL to the list of scanned URLs"""
        if url not in self.results["urls_scanned"]:
            self.results["urls_scanned"].append(url)
    
    def to_dict(self):
        """Convert the scan result to a dictionary"""
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "status": self.status,
            "results": self.results
        }
    
    def to_json(self):
        """Convert the scan result to a JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data):
        """Create a ScanResult instance from a dictionary"""
        result = cls(data["target_url"], data["scan_type"])
        result.id = data["id"]
        result.start_time = datetime.fromisoformat(data["start_time"])
        if data["end_time"]:
            result.end_time = datetime.fromisoformat(data["end_time"])
        result.duration = data["duration"]
        result.status = data["status"]
        result.results = data["results"]
        return result
    
    @classmethod
    def from_json(cls, json_str):
        """Create a ScanResult instance from a JSON string"""
        data = json.loads(json_str)
        return cls.from_dict(data)


class ScanResultsManager:
    def __init__(self, storage_dir="scan_results"):
        self.storage_dir = storage_dir
        
        # Create storage directory if it doesn't exist
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
    
    def save_result(self, scan_result):
        """Save a scan result to disk"""
        filename = f"{scan_result.id}.json"
        filepath = os.path.join(self.storage_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(scan_result.to_json())
        
        return filepath
    
    def load_result(self, scan_id):
        """Load a scan result from disk"""
        filename = f"{scan_id}.json"
        filepath = os.path.join(self.storage_dir, filename)
        
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'r') as f:
            json_data = f.read()
        
        return ScanResult.from_json(json_data)
    
    def list_results(self, limit=10):
        """List recent scan results"""
        results = []
        
        # Get all JSON files in the storage directory
        files = [f for f in os.listdir(self.storage_dir) if f.endswith('.json')]
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: os.path.getmtime(os.path.join(self.storage_dir, x)), reverse=True)
        
        # Load the most recent scan results
        for filename in files[:limit]:
            filepath = os.path.join(self.storage_dir, filename)
            with open(filepath, 'r') as f:
                json_data = f.read()
            
            result = ScanResult.from_json(json_data)
            results.append(result)
        
        return results
    
    def delete_result(self, scan_id):
        """Delete a scan result"""
        filename = f"{scan_id}.json"
        filepath = os.path.join(self.storage_dir, filename)
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        
        return False