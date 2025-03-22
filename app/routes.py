from flask import Blueprint, request, jsonify, render_template
from app.scanner.phishing import analyze_phishing
from app.scanner.xss import analyze_xss
from app.scanner.csrf import analyze_csrf
from app.api.safe_browsing import check_safe_browsing

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('popup.html')

@main.route('/settings')
def settings():
    return render_template('settings.html')

@main.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    html_content = data.get('html')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    results = {
        'url': url,
        'phishing': {},
        'xss': {},
        'csrf': {},
        'safe_browsing': {}
    }
    
    # Check Safe Browsing API
    safe_browsing_result = check_safe_browsing(url)
    results['safe_browsing'] = safe_browsing_result
    
    # Analyze for phishing
    phishing_result = analyze_phishing(url, html_content)
    results['phishing'] = phishing_result
    
    # Analyze for XSS
    xss_result = analyze_xss(html_content)
    results['xss'] = xss_result
    
    # Analyze for CSRF
    csrf_result = analyze_csrf(html_content)
    results['csrf'] = csrf_result
    
    # Calculate overall risk score
    risk_score = 0
    
    if phishing_result.get('risk_level') == 'high':
        risk_score += 40
    elif phishing_result.get('risk_level') == 'medium':
        risk_score += 20
    elif phishing_result.get('risk_level') == 'low':
        risk_score += 5
    
    if xss_result.get('vulnerable'):
        risk_score += 30
    
    if csrf_result.get('vulnerable'):
        risk_score += 20
    
    if safe_browsing_result.get('threats'):
        risk_score += 50
    
    results['risk_score'] = min(risk_score, 100)
    
    return jsonify(results)

@main.route('/api/educate/<threat_type>')
def educate(threat_type):
    education_content = {
        'phishing': {
            'title': 'About Phishing',
            'description': 'Phishing is a type of social engineering attack where attackers trick users into revealing sensitive information by impersonating trusted entities.',
            'prevention': [
                'Check the URL carefully before entering credentials',
                'Look for SSL certification (https)',
                'Be wary of urgent requests for personal information',
                'Check for grammar and spelling errors'
            ]
        },
        'xss': {
            'title': 'About Cross-Site Scripting (XSS)',
            'description': 'XSS is a web security vulnerability that allows attackers to inject malicious scripts into webpages viewed by other users.',
            'prevention': [
                'Use content security policies',
                'Filter and validate all user inputs',
                'Encode output data',
                'Keep your browser and extensions updated'
            ]
        },
        'csrf': {
            'title': 'About Cross-Site Request Forgery (CSRF)',
            'description': 'CSRF is an attack that forces users to execute unwanted actions on websites where they are authenticated.',
            'prevention': [
                'Use anti-CSRF tokens',
                'Check the referer header',
                'Log out of websites when not in use',
                'Use SameSite cookies'
            ]
        }
    }
    
    if threat_type in education_content:
        return jsonify(education_content[threat_type])
    else:
        return jsonify({'error': 'Education content not found'}), 404