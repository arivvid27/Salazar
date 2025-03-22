from bs4 import BeautifulSoup

def analyze_csrf(html_content):
    """
    Analyze HTML content for potential CSRF vulnerabilities
    """
    if not html_content:
        return {"vulnerable": False, "risk_factors": [], "recommendations": []}
    
    soup = BeautifulSoup(html_content, 'lxml')
    risk_factors = []
    
    # Find all forms
    forms = soup.find_all('form')
    
    if not forms:
        return {"vulnerable": False, "risk_factors": [], "recommendations": []}
    
    for form in forms:
        # Check for CSRF token in the form
        has_csrf_token = False
        
        # Look for input fields with names commonly used for CSRF tokens
        csrf_field_names = ['csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken', 
                            'authenticity_token', '_token', 'token', 'xsrf', 'nonce']
        
        for field_name in csrf_field_names:
            if soup.find('input', attrs={'name': lambda x: x and field_name.lower() in x.lower()}):
                has_csrf_token = True
                break
        
        # If no CSRF token input field, check for hidden meta tags that might be used for CSRF protection
        if not has_csrf_token:
            meta_csrf = soup.find('meta', attrs={'name': lambda x: x and 'csrf' in x.lower()})
            if meta_csrf:
                has_csrf_token = True
        
        # Check for specific header that might indicate CSRF protection
        # This is a simple check; in reality, we would need to look at HTTP headers
        meta_headers = soup.find_all('meta', attrs={'http-equiv': True})
        header_csrf = any('csrf' in str(meta).lower() for meta in meta_headers)
        
        if not has_csrf_token and not header_csrf:
            form_id = form.get('id', '')
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            # Only flag non-GET forms without CSRF protection
            if form_method != 'get':
                risk_detail = f"Form (ID: {form_id or 'unnamed'}, Action: {form_action or 'current page'}) "
                risk_detail += "does not appear to have CSRF protection"
                risk_factors.append(risk_detail)
    
    # Check for cookies that aren't protected
    # This is a simplistic check that would need enhancement in a real system
    script_tags = soup.find_all('script')
    cookie_scripts = [script for script in script_tags if script.string and 'document.cookie' in script.string]
    
    if cookie_scripts and not any('SameSite' in script.string for script in cookie_scripts):
        risk_factors.append("Cookies are being set without SameSite attribute")
    
    # Generate recommendations
    recommendations = []
    if risk_factors:
        recommendations = [
            "Implement CSRF tokens for all state-changing forms",
            "Use SameSite=Strict or SameSite=Lax for cookies",
            "Implement the 'Double Submit Cookie' pattern for AJAX requests",
            "Add CSRF protection middleware to your web framework",
            "Consider using the 'SameSite' cookie attribute for session cookies",
            "Implement proper Cross-Origin Resource Sharing (CORS) policies"
        ]
    
    return {
        "vulnerable": len(risk_factors) > 0,
        "risk_factors": risk_factors,
        "recommendations": recommendations
    }