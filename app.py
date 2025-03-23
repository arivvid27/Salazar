from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import logging
import os
import json
import time
import validators
from datetime import datetime

from config import Config

from utils.web_crawler import WebCrawler
from utils.xss_scanner import XSSScanner
from utils.csrf_scanner import CSRFScanner

from models.threat_model import ScanResult, ScanResultsManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

web_crawler = WebCrawler(Config)
xss_scanner = XSSScanner(Config)
csrf_scanner = CSRFScanner(Config)

if not os.path.exists('scan_results'):
    os.makedirs('scan_results')

results_manager = ScanResultsManager('scan_results')

active_scans = {}

@app.route('/')
def index():
    """Render the homepage"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    target_url = request.form.get('url', '').strip()
    
    if not target_url:
        flash('Please enter a URL to scan', 'error')
        return redirect(url_for('index'))
    
    if not validators.url(target_url):
        flash('Please enter a valid URL', 'error')
        return redirect(url_for('index'))
    
    scan_result = ScanResult(target_url)
    active_scans[scan_result.id] = scan_result
    
    session['current_scan_id'] = scan_result.id
    
    return redirect(url_for('scan_status', scan_id=scan_result.id))

@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    """Show the scan status page"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
        flash('Scan not found', 'error')
        return redirect(url_for('index'))
    
    if scan_result.status == "pending":
        scan_result.status = "running"
        
        try:
            perform_scan(scan_result)
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            scan_result.status = "error"
            flash(f'Error during scan: {str(e)}', 'error')
    
    if scan_result.status == "running":
        return render_template('scan_status.html', scan=scan_result)
    
    return redirect(url_for('scan_results', scan_id=scan_id))

@app.route('/scan/<scan_id>/results')
def scan_results(scan_id):
    """Show the scan results page"""
    scan_result = active_scans.get(scan_id)
    
    if not scan_result:
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
        urls, page_contents = web_crawler.crawl(target_url)
        
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
        
        for url in urls:
            content = page_contents.get(url)
            if not content:
                logger.warning(f"No content for {url}, skipping")
                continue
            
            scan_result.add_scanned_url(url)
            
            xss_result = xss_scanner.scan_page(url, content)
            scan_result.add_xss_result(url, xss_result)
            
            _, headers = web_crawler.fetch_page(url)
            csrf_result = csrf_scanner.scan_page(url, content, headers)
            scan_result.add_csrf_result(url, csrf_result)
            
            time.sleep(0.2)
        
        scan_result.complete_scan()
        
        with open(f"scan_results/{scan_result.id}.json", "w") as f:
            json.dump(scan_result.to_dict(), f, indent=2)
        
        logger.info(f"Scan completed for {target_url}")
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        scan_result.status = "error"
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
