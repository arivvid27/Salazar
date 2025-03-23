from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import logging
import os
import json
import time
import validators
from datetime import datetime

# Import configuration
from config import Config

# Import utility modules
from utils.web_crawler import WebCrawler
from utils.xss_scanner import XSSScanner
from utils.csrf_scanner import CSRFScanner

# Import models
from models.threat_model import ScanResult, ScanResultsManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize components
web_crawler = WebCrawler(Config)
xss_scanner = XSSScanner(Config)
csrf_scanner = CSRFScanner(Config)

# Create a storage directory for scan results if it doesn't exist
if not os.path.exists('scan_results'):
    os.makedirs('scan_results')

# Initialize scan results manager
results_manager = ScanResultsManager('scan_results')

# Store active scans in memory
active_scans = {}

@app.route('/')
def index():
    """Render the homepage"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    target_url = request.form.get('url', '').strip()
    
    # Validate the URL
    if not target_url:
        flash('Please enter a URL to scan', 'error')
        return redirect(url_for('index'))
    
    if not validators.url(target_url):
        flash('Please enter a valid URL', 'error')
        return redirect(url_for('index'))
    
    # Create a new scan result
    scan_result = ScanResult(target_url)
    active_scans[scan_result.id] = scan_result
    
    # Store the scan ID in the session
    session['current_scan_id'] = scan_result.id
    
    # Start the scan (non-blocking)
    return redirect(url_for('scan_status', scan_id=scan_result.id))

@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    """Show the scan status page"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
        flash('Scan not found', 'error')
        return redirect(url_for('index'))
    
    # If scan is pending, start it now
    if scan_result.status == "pending":
        # Set status to running
        scan_result.status = "running"
        
        try:
            # Start the scan
            perform_scan(scan_result)
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            scan_result.status = "error"
            flash(f'Error during scan: {str(e)}', 'error')
    
    # If scan is still running, show status page
    if scan_result.status == "running":
        return render_template('scan_status.html', scan=scan_result)
    
    # If scan is completed or errored, redirect to results
    return redirect(url_for('scan_results', scan_id=scan_id))

@app.route('/scan/<scan_id>/results')
def scan_results(scan_id):
    """Show the scan results page"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
        # Try to load from storage
        try:
            with open(f"scan_results/{scan_id}.json", "r") as f:
                scan_data = json.load(f)
                scan_result = ScanResult.from_dict(scan_data)
        except (FileNotFoundError, json.JSONDecodeError):
            flash('Scan not found', 'error')
            return redirect(url_for('index'))
    
    return render_template('results.html', scan=scan_result)

@app.route('/api/scan/<scan_id>/status')
def api_scan_status(scan_id):
    """API endpoint to get scan status"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "id": scan_result.id,
        "status": scan_result.status,
        "target_url": scan_result.target_url,
        "progress": {
            "urls_scanned": len(scan_result.results.get("urls_scanned", [])),
            "xss_results": len(scan_result.results.get("xss", {})),
            "csrf_results": len(scan_result.results.get("csrf", {}))
        }
    })

@app.route('/api/scan/<scan_id>/results')
def api_scan_results(scan_id):
    """API endpoint to get scan results"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
        # Try to load from storage
        try:
            with open(f"scan_results/{scan_id}.json", "r") as f:
                scan_data = json.load(f)
                scan_result = ScanResult.from_dict(scan_data)
        except (FileNotFoundError, json.JSONDecodeError):
            return jsonify({"error": "Scan not found"}), 404
    
    return jsonify(scan_result.to_dict())

def perform_scan(scan_result):
    """Perform the actual scanning"""
    target_url = scan_result.target_url
    logger.info(f"Starting scan for {target_url}")
    
    try:
        # Crawl the website
        urls, page_contents = web_crawler.crawl(target_url)
        
        # If no URLs were found, just scan the target URL
        if not urls:
            logger.warning(f"No URLs found during crawl of {target_url}")
            content, headers = web_crawler.fetch_page(target_url)
            if content:
                page_contents = {target_url: content}
                urls = [target_url]
                scan_result.add_scanned_url(target_url)
            else:
                logger.error(f"Failed to fetch content for {target_url}")
                scan_result.status = "error"
                return
        
        # Scan each page for vulnerabilities
        for url in urls:
            content = page_contents.get(url)
            if not content:
                logger.warning(f"No content for {url}, skipping")
                continue
            
            # Add to scanned URLs list
            scan_result.add_scanned_url(url)
            
            # Scan for XSS
            xss_result = xss_scanner.scan_page(url, content)
            scan_result.add_xss_result(url, xss_result)
            
            # Scan for CSRF
            _, headers = web_crawler.fetch_page(url)
            csrf_result = csrf_scanner.scan_page(url, content, headers)
            scan_result.add_csrf_result(url, csrf_result)
            
            # Small delay to avoid overloading
            time.sleep(0.2)
        
        # Mark scan as complete
        scan_result.complete_scan()
        
        # Save results to disk
        with open(f"scan_results/{scan_result.id}.json", "w") as f:
            json.dump(scan_result.to_dict(), f, indent=2)
        
        logger.info(f"Scan completed for {target_url}")
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        scan_result.status = "error"
        # Save partial results
        with open(f"scan_results/{scan_result.id}.json", "w") as f:
            json.dump(scan_result.to_dict(), f, indent=2)

@app.template_filter('format_datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object to string"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if value:
        return value.strftime(format)
    return ""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)