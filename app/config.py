import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') or 'AIzaSyCfb1AlLLYl9V3gEODD1JKwsuLTqQi0E3Q'
    SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY') or ''
    SAFE_BROWSING_CLIENT_ID = 'muninn-web-security-scanner'
    SAFE_BROWSING_CLIENT_VERSION = '1.0.0'