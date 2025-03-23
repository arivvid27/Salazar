import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'muninn-default-secret-key')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    
    # Scanner settings
    MAX_SCAN_DEPTH = 3  # Maximum depth for web crawling
    MAX_URLS_TO_SCAN = 15  # Maximum number of URLs to scan per domain
    SCAN_TIMEOUT = 30  # Timeout for each request in seconds
    
    # User-Agent for requests
    USER_AGENT = 'Muninn Security Scanner/1.0'