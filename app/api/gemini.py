import json
import google.generativeai as genai
from app.config import Config

# Configure the Gemini API
genai.configure(api_key=Config.GEMINI_API_KEY)

def analyze_with_gemini(url, form_contexts):
    """
    Use Google Gemini to analyze potential phishing content
    
    Args:
        url: The URL of the webpage
        form_contexts: List of dictionaries containing form data and surrounding text
        
    Returns:
        Dictionary with phishing analysis results
    """
    # Create a prompt for Gemini
    prompt = f"""
    Analyze this webpage for phishing indicators. The URL is: {url}
    
    Form information:
    {json.dumps(form_contexts, indent=2)}
    
    Please analyze this for phishing likelihood. Consider:
    1. Does the URL match what you'd expect for the brand it appears to represent?
    2. Are there signs of urgency or threats in the text?
    3. Are the forms collecting sensitive information?
    4. Are there grammatical errors or awkward phrasing?
    5. Does this appear to be impersonating a known brand?
    
    Respond in JSON format with the following fields:
    - phishing_confidence: a number between 0 and 1 indicating likelihood of phishing
    - indicators: list of specific phishing indicators found
    - explanation: brief explanation of the analysis
    """
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        
        # Try to parse the response as JSON
        try:
            # Extract JSON from the response (the API might wrap it in markdown code blocks)
            response_text = response.text
            
            # If the response contains a code block, extract the JSON from it
            if "```json" in response_text:
                json_content = response_text.split("```json")[1].split("```")[0].strip()
                result = json.loads(json_content)
            else:
                # Otherwise, try to parse the whole response
                result = json.loads(response_text)
            
            return result
        except json.JSONDecodeError:
            # If we can't parse the JSON, extract key information manually
            response_text = response.text.lower()
            
            # Estimate phishing confidence based on the content
            if "high likelihood" in response_text or "definitely phishing" in response_text:
                confidence = 0.9
            elif "moderate likelihood" in response_text or "possibly phishing" in response_text:
                confidence = 0.6
            elif "low likelihood" in response_text or "probably not phishing" in response_text:
                confidence = 0.2
            else:
                confidence = 0.5
            
            # Extract potential indicators
            indicators = []
            if "suspicious url" in response_text:
                indicators.append("Suspicious URL structure")
            if "sensitive information" in response_text:
                indicators.append("Collecting sensitive information")
            if "grammar" in response_text and ("error" in response_text or "poor" in response_text):
                indicators.append("Poor grammar or spelling")
            if "impersonat" in response_text:
                indicators.append("Potential brand impersonation")
            if "urgency" in response_text or "threat" in response_text:
                indicators.append("Creating false sense of urgency")
            
            return {
                "phishing_confidence": confidence,
                "indicators": indicators,
                "explanation": "Analysis based on form context and URL examination."
            }
    
    except Exception as e:
        print(f"Error using Gemini API: {e}")
        # Return a fallback result
        return {
            "phishing_confidence": 0.5,
            "indicators": ["Unable to perform full AI analysis"],
            "explanation": "Error in AI analysis service. Using fallback analysis."
        }