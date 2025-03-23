import re
import logging
from bs4 import BeautifulSoup
import google.generativeai as genai

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, config):
        self.api_key = config.GEMINI_API_KEY
        self.setup_genai()
        
    def setup_genai(self):
        """Configure the Gemini API client"""
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-lite')
        
    def scan_page(self, url, content):
        """
        Scan a page for potential XSS vulnerabilities.
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
            
            
            scripts = soup.find_all('script')
            script_contents = [script.string for script in scripts if script.string]
            
            
            inputs = soup.find_all('input')
            forms = soup.find_all('form')
            
           
            event_handlers = []
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith('on'):
                        event_handlers.append((attr, tag.get(attr)))
            
            
            url_params = {}
            if '?' in url:
                query_string = url.split('?', 1)[1]
                if '&' in query_string:
                    params = query_string.split('&')
                    for param in params:
                        if '=' in param:
                            key, value = param.split('=', 1)
                            url_params[key] = value
                else:
                    if '=' in query_string:
                        key, value = query_string.split('=', 1)
                        url_params[key] = value
            
            
            js_sinks = self._find_js_sinks(content)
            dom_xss_patterns = self._find_dom_xss_patterns(content)
            
            
            if js_sinks:
                results["vulnerabilities"].append({
                    "type": "JS Sinks",
                    "description": "JavaScript functions that can be used in XSS attacks if not properly sanitized",
                    "details": js_sinks
                })
            
            if dom_xss_patterns:
                results["vulnerabilities"].append({
                    "type": "DOM XSS Patterns",
                    "description": "Patterns that may indicate DOM-based XSS vulnerabilities",
                    "details": dom_xss_patterns
                })
            
            if url_params:
                results["vulnerabilities"].append({
                    "type": "URL Parameters",
                    "description": "URL parameters that could be injection points",
                    "details": url_params
                })
            
            
            analysis_content = {
                "url": url,
                "scripts": script_contents[:5],  
                "input_count": len(inputs),
                "form_count": len(forms),
                "event_handlers": event_handlers[:10],  
                "url_params": url_params,
                "js_sinks": js_sinks,
                "dom_patterns": dom_xss_patterns
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
            elif len(results["vulnerabilities"]) > 3 or ai_result.get("risk_level") == "High":
                results["risk_level"] = "High"
            elif len(results["vulnerabilities"]) > 1:
                results["risk_level"] = "Medium"
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning for XSS in {url}: {str(e)}")
            return {
                "status": "error", 
                "message": f"Error scanning for XSS: {str(e)}",
                "url": url,
                "risk_level": "Unknown"
            }
    
    def _find_js_sinks(self, content):
        """Find JavaScript sinks that could be vulnerable to XSS"""
        dangerous_sinks = [
            'eval\\s*\\(', 'document\\.write\\s*\\(', 'innerHTML\\s*=', 'outerHTML\\s*=',
            'insertAdjacentHTML\\s*\\(', 'document\\.execCommand\\s*\\(',
            'window\\.location', 'document\\.URL', 'document\\.documentURI',
            'document\\.location', 'location\\.href', 'location\\.search', 'location\\.hash'
        ]
        
        results = {}
        for sink in dangerous_sinks:
            matches = re.findall(sink, content, re.IGNORECASE)
            if matches:
                sink_name = sink.replace('\\s*', ' ').replace('\\(', '(').replace('\\', '')
                results[sink_name] = len(matches)
        
        return results
    
    def _find_dom_xss_patterns(self, content):
        """Find patterns that may indicate DOM-based XSS vulnerabilities"""
        dom_xss_patterns = [
            'document\\.getElementById\\s*\\([^)]*\\)\\.innerHTML\\s*=',
            'document\\.getElementById\\s*\\([^)]*\\)\\.outerHTML\\s*=',
            '\\$\\s*\\([^)]*\\)\\.html\\s*\\(',
            '\\.html\\s*\\(.*location',
            '\\.html\\s*\\(.*document\\.URL',
            '\\.html\\s*\\(.*document\\.documentURI',
            '\\.html\\s*\\(.*document\\.location',
            'document\\.write\\s*\\(.*location',
            'document\\.write\\s*\\(.*document\\.URL',
            'document\\.write\\s*\\(.*document\\.documentURI',
            'document\\.write\\s*\\(.*document\\.location',
        ]
        
        results = {}
        for pattern in dom_xss_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                pattern_name = pattern.replace('\\s*', ' ').replace('\\(', '(').replace('\\)', ')').replace('\\', '')
                results[pattern_name] = len(matches)
        
        return results
    
    def _analyze_with_ai(self, analysis_content, raw_content):
        """
        Use Gemini to analyze potential XSS vulnerabilities
        """
        try:
            # Create a prompt for the AI to analyze the content
            prompt = f"""
            Analyze this website for XSS (Cross-Site Scripting) vulnerabilities. I'll provide you with key information extracted from the page.
            
            URL: {analysis_content['url']}
            
            Number of input fields: {analysis_content['input_count']}
            Number of forms: {analysis_content['form_count']}
            
            URL Parameters: {analysis_content['url_params']}
            
            JavaScript sinks found (potential vulnerability points):
            {analysis_content['js_sinks']}
            
            DOM XSS patterns found:
            {analysis_content['dom_patterns']}
            
            Event handlers found (first 10):
            {analysis_content['event_handlers']}
            
            Scripts found (first few):
            {', '.join(analysis_content['scripts'][:3]) if analysis_content['scripts'] else 'None'}
            
            Please analyze this information and determine if there are potential XSS vulnerabilities. Provide:
            1. A brief analysis of the XSS risk
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
            logger.error(f"Error in AI analysis for XSS: {str(e)}")
            return {
                "analysis": f"AI analysis error: {str(e)}",
                "risk_level": "Medium",
                "vulnerabilities": []
            }