import re
from bs4 import BeautifulSoup

def analyze_xss(html_content):
    """
    Analyze HTML content for potential XSS vulnerabilities
    """
    if not html_content:
        return {"vulnerable": False, "risk_factors": [], "recommendations": []}
    
    soup = BeautifulSoup(html_content, 'lxml')
    risk_factors = []
    
    # Check for inline JavaScript with potentially dangerous patterns
    script_tags = soup.find_all('script')
    for script in script_tags:
        script_content = script.string
        if script_content:
            # Check for document.location usage without validation
            if 'document.location' in script_content and not ('indexOf' in script_content or 'search' in script_content):
                risk_factors.append("Unvalidated use of document.location in script")
            
            # Check for direct DOM manipulation with user input
            if 'document.write' in script_content and ('location' in script_content or 'URL' in script_content):
                risk_factors.append("Potentially unsafe document.write with location data")
            
            # Check for eval() usage
            if 'eval(' in script_content:
                risk_factors.append("Use of eval() function detected")
            
            # Check for innerHTML assignment
            if '.innerHTML' in script_content and ('location' in script_content or 'URL' in script_content):
                risk_factors.append("Potentially unsafe innerHTML assignment with location data")
    
    # Check for event handlers that might be vulnerable
    elements_with_handlers = soup.select('[onclick], [onload], [onmouseover], [onerror]')
    for element in elements_with_handlers:
        for attr in ['onclick', 'onload', 'onmouseover', 'onerror']:
            handler = element.get(attr)
            if handler and ('location' in handler or 'URL' in handler or 'document.cookie' in handler):
                risk_factors.append(f"Potentially unsafe {attr} handler using location or cookie data")
    
    # Check for input fields that might reflect user input
    input_fields = soup.find_all('input')
    forms = soup.find_all('form')
    
    if input_fields and not any('autocomplete="off"' in str(field) for field in input_fields):
        has_sanitization = False
        
        # Check if there's JavaScript that might be sanitizing input
        for script in script_tags:
            script_content = script.string or ""
            if any(term in script_content for term in ['encodeURIComponent', 'escapeHTML', 'sanitize', 'DOMPurify']):
                has_sanitization = True
                break
        
        if not has_sanitization:
            risk_factors.append("Input fields present without clear client-side sanitization")
    
    # Check for suspicious URL parameters being used in the page
    # This is a simplistic check that would need enhancement in a real system
    param_regex = r'[\?&][^=]+=([^&]*)'
    params = re.findall(param_regex, html_content)
    
    for param in params:
        if '<' in param or '>' in param or 'script' in param.lower():
            risk_factors.append("URL parameter contains potentially malicious content")
    
    # Check for Meta Content-Security-Policy
    meta_csp = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
    if not meta_csp:
        risk_factors.append("No Content-Security-Policy meta tag found")
    
    # Generate recommendations based on findings
    recommendations = []
    if risk_factors:
        recommendations = [
            "Implement Content Security Policy (CSP)",
            "Validate and sanitize all user inputs",
            "Use safe DOM manipulation methods (textContent instead of innerHTML)",
            "Avoid using eval() and similar functions",
            "Encode output using appropriate context-specific encoding",
            "Consider using a security library like DOMPurify for sanitization"
        ]
    
    return {
        "vulnerable": len(risk_factors) > 0,
        "risk_factors": risk_factors,
        "recommendations": recommendations
    }