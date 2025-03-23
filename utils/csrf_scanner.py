import re
import logging
from bs4 import BeautifulSoup
import google.generativeai as genai

logger = logging.getLogger(__name__)

class CSRFScanner:
    def __init__(self, config):
        self.api_key = config.GEMINI_API_KEY
        self.setup_genai()
        
    def setup_genai(self):
        """Configure the Gemini API client"""
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-lite')
        
    def scan_page(self, url, content, headers=None):
        """
        Scan a page for potential CSRF vulnerabilities.
        Returns a dictionary of findings.
        """
        if not content:
            return {"status": "error", "message": "No content to analyze"}
        
        results = {
            "url": url,
            "vulnerabilities": [],
            "risk_level": "Low",
            "ai_analysis": ""
        }
        
        try:
            
            soup = BeautifulSoup(content, 'html.parser')
            
            
            forms = soup.find_all('form')
            
            
            form_analysis = []
            has_csrf_token = False
            
            for i, form in enumerate(forms):
                form_data = {
                    "id": form.get('id', f'form_{i}'),
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get').upper(),
                    "inputs": [],
                    "has_csrf_token": False
                }
                
                
                if form_data["method"] != "POST":
                    continue
                
                
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_data = {
                        "name": input_field.get('name', ''),
                        "type": input_field.get('type', ''),
                        "value": input_field.get('value', '')
                    }
                    form_data["inputs"].append(input_data)
                    
                    
                    input_name = input_data["name"].lower()
                    input_type = input_data["type"].lower()
                    
                    if (
                        input_type == 'hidden' and 
                        ('csrf' in input_name or 'token' in input_name or '_token' in input_name)
                    ):
                        form_data["has_csrf_token"] = True
                        has_csrf_token = True
                
                form_analysis.append(form_data)
            
            # 
            csrf_headers = False
            same_site_cookies = False
            
            if headers:
                
                if any(h.lower() == 'x-csrf-token' for h in headers.keys()):
                    csrf_headers = True
                
                # 
                if 'Set-Cookie' in headers:
                    cookie_header = headers['Set-Cookie']
                    same_site_cookies = 'SameSite=Strict' in cookie_header or 'SameSite=Lax' in cookie_header
            
            # 
            if forms and not has_csrf_token and not csrf_headers and not same_site_cookies:
                results["vulnerabilities"].append({
                    "type": "Missing CSRF Protection",
                    "description": "Forms found with no apparent CSRF protection",
                    "details": "No CSRF tokens, headers, or SameSite cookie attributes detected"
                })
            
            
            analysis_content = {
                "url": url,
                "forms": form_analysis,
                "has_csrf_token": has_csrf_token,
                "csrf_headers": csrf_headers,
                "same_site_cookies": same_site_cookies
            }
            
            
            ai_result = self._analyze_with_ai(analysis_content, content)
            
            if ai_result:
                results["ai_analysis"] = ai_result.get("analysis", "AI analysis failed")
                results["risk_level"] = ai_result.get("risk_level", "Medium")
                
                if ai_result.get("vulnerabilities"):
                    for vuln in ai_result.get("vulnerabilities"):
                        results["vulnerabilities"].append(vuln)
            
            
            if not results["vulnerabilities"]:
                results["risk_level"] = "Low"
            elif len(results["vulnerabilities"]) > 2 or ai_result.get("risk_level") == "High":
                results["risk_level"] = "High"
            elif len(results["vulnerabilities"]) > 0:
                results["risk_level"] = "Medium"
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning for CSRF in {url}: {str(e)}")
            return {
                "status": "error", 
                "message": f"Error scanning for CSRF: {str(e)}",
                "url": url,
                "risk_level": "Unknown"
            }
    
    def _analyze_with_ai(self, analysis_content, raw_content):
        """
        Use Gemini to analyze potential CSRF vulnerabilities
        """
        try:
            
            prompt = f"""
            Analyze this website for CSRF (Cross-Site Request Forgery) vulnerabilities. I'll provide you with key information extracted from the page.
            
            URL: {analysis_content['url']}
            
            Forms analysis:
            {analysis_content['forms']}
            
            CSRF Protection Detected:
            - CSRF tokens in forms: {'Yes' if analysis_content['has_csrf_token'] else 'No'}
            - CSRF headers: {'Yes' if analysis_content['csrf_headers'] else 'No'}
            - SameSite cookie attributes: {'Yes' if analysis_content['same_site_cookies'] else 'No'}
            
            Please analyze this information and determine if there are potential CSRF vulnerabilities. Provide:
            1. A brief analysis of the CSRF risk
            2. A risk level (Low, Medium, or High)
            3. A list of specific vulnerabilities found (if any)
            
            Format your response as JSON:
            {{
                "analysis": "Your detailed analysis here",
                "risk_level": "Low/Medium/High",
                "vulnerabilities": [
                    {{
                        "type": "Vulnerability type",
                        "description": "Brief description",
                        "details": "Technical details",
                        "remediation": "How to fix it"
                    }}
                ]
            }}
            
            If you can't detect any vulnerabilities, still provide an analysis and set the risk level appropriately.
            """
            
            
            response = self.model.generate_content(prompt)
            response_text = response.text
            
            
            import json
            import re
            
            
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                
                json_str = response_text
            
            try:
                return json.loads(json_str)
            except:
                
                json_match = re.search(r'({[\s\S]*})', json_str)
                if json_match:
                    try:
                        return json.loads(json_match.group(1))
                    except:
                        logger.error("Failed to parse AI response JSON")
                        return {
                            "analysis": "AI analysis failed to parse the JSON response",
                            "risk_level": "Medium",
                            "vulnerabilities": []
                        }
            
        except Exception as e:
            logger.error(f"Error in AI analysis for CSRF: {str(e)}")
            return {
                "analysis": f"AI analysis error: {str(e)}",
                "risk_level": "Medium",
                "vulnerabilities": []
            }