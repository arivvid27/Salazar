import re
import urllib.parse
from bs4 import BeautifulSoup
from app.api.gemini import analyze_with_gemini
from app.api.safe_browsing import check_safe_browsing

def analyze_phishing(url, html_content):
    """
    Analyze a URL and its HTML content for phishing indicators
    """
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    # Initialize risk factors
    risk_factors = []
    risk_level = "low"
    
    # Check for suspicious URL patterns
    suspicious_patterns = [
        r'paypal.*\.com(?!\.paypal\.com)',  # Paypal lookalike
        r'google.*\.com(?!\.google\.com)',  # Google lookalike
        r'facebook.*\.com(?!\.facebook\.com)',  # Facebook lookalike
        r'apple.*\.com(?!\.apple\.com)',  # Apple lookalike
        r'microsoft.*\.com(?!\.microsoft\.com)',  # Microsoft lookalike
        r'amazon.*\.com(?!\.amazon\.com)',  # Amazon lookalike
        r'secure.*bank',  # Secure banking lookalike
        r'verify.*account',  # Account verification lookalike
        r'login.*secure',  # Secure login lookalike
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            risk_factors.append(f"Domain matches suspicious pattern: {domain}")
    
    # Check for IP address in domain
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        risk_factors.append("URL contains an IP address instead of a domain name")
        risk_level = "high"
    
    # Check for excessive subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        risk_factors.append(f"Excessive number of subdomains: {subdomain_count}")
    
    # Check for misleading subdomains
    if '.' in domain:
        parts = domain.split('.')
        if len(parts) > 2:
            for trusted_domain in ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'bank']:
                if any(trusted_domain in part.lower() for part in parts[:-2]):
                    risk_factors.append(f"Potentially misleading subdomain using trusted brand: {trusted_domain}")
                    risk_level = "medium"
    
    # Check for typosquatting (common misspellings of popular domains)
    typosquatting_examples = {
        'paypa1': 'paypal',
        'g00gle': 'google',
        'faceb00k': 'facebook',
        'micosoft': 'microsoft',
        'amaz0n': 'amazon',
    }
    
    for typo, original in typosquatting_examples.items():
        if typo in domain.lower():
            risk_factors.append(f"Possible typosquatting of {original}")
            risk_level = "high"
    
    # Check URL for suspicious terms
    suspicious_terms = ['login', 'signin', 'verify', 'validation', 'authenticate', 'password', 'credential', 'secure']
    path = parsed_url.path.lower()
    
    for term in suspicious_terms:
        if term in path:
            risk_factors.append(f"URL path contains suspicious term: {term}")
    
    # Use AI to analyze the content if HTML is provided
    if html_content:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Check for login forms
        login_forms = soup.find_all('form')
        if login_forms:
            # Extract text around the forms
            form_contexts = []
            for form in login_forms:
                # Get form fields
                input_fields = form.find_all('input')
                password_field = any(field.get('type') == 'password' for field in input_fields)
                
                if password_field:
                    # This is likely a login form
                    context = {}
                    context['action'] = form.get('action', '')
                    context['method'] = form.get('method', '')
                    context['fields'] = [{'name': field.get('name', ''), 'type': field.get('type', '')} 
                                         for field in input_fields]
                    
                    # Get text around the form
                    preceding_text = ' '.join([s.strip() for s in form.find_all_previous(string=True, limit=10)])
                    following_text = ' '.join([s.strip() for s in form.find_all_next(string=True, limit=10)])
                    
                    context['surrounding_text'] = preceding_text[:200] + "..." + following_text[:200]
                    form_contexts.append(context)
            
            if form_contexts:
                # Use Gemini to analyze the form contexts
                gemini_analysis = analyze_with_gemini(url, form_contexts)
                
                if gemini_analysis.get('phishing_confidence') > 0.7:
                    risk_factors.append("AI analysis indicates high likelihood of phishing")
                    risk_level = "high"
                elif gemini_analysis.get('phishing_confidence') > 0.4:
                    risk_factors.append("AI analysis indicates moderate likelihood of phishing")
                    risk_level = "medium"
                
                # Add any specific indicators detected by Gemini
                for indicator in gemini_analysis.get('indicators', []):
                    risk_factors.append(f"AI detected: {indicator}")
    
    # Check domain age (simulated in this implementation)
    # In a real app, you would query WHOIS or similar services
    domain_age_simulation = len(domain) % 10  # Just for simulation
    if domain_age_simulation < 3:
        risk_factors.append("Domain appears to be recently registered")
        if risk_level == "low":
            risk_level = "medium"
    
    # Determine risk level based on factors
    if len(risk_factors) > 5:
        risk_level = "high"
    elif len(risk_factors) > 2:
        risk_level = "medium"
    
    return {
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "domain": domain,
        "recommendations": get_recommendations(risk_level)
    }

def get_recommendations(risk_level):
    """
    Return recommendations based on risk level
    """
    if risk_level == "high":
        return [
            "Do not enter any personal information on this site",
            "Leave this website immediately",
            "Report this website to your browser or phishing authorities",
            "If you've already entered credentials, change your passwords immediately"
        ]
    elif risk_level == "medium":
        return [
            "Proceed with extreme caution",
            "Verify the website's legitimacy through other means",
            "Look for secure connection (HTTPS) and valid certificate",
            "Contact the company directly through official channels to verify"
        ]
    else:
        return [
            "Always be cautious when entering personal information",
            "Verify the website's URL before proceeding",
            "Look for secure connection (HTTPS)"
        ]