import requests
from bs4 import BeautifulSoup
import tldextract
import urllib.parse
import validators
from requests.exceptions import RequestException
import logging
import time

logger = logging.getLogger(__name__)

class WebCrawler:
    def __init__(self, config):
        self.max_depth = config.MAX_SCAN_DEPTH
        self.max_urls = config.MAX_URLS_TO_SCAN
        self.timeout = config.SCAN_TIMEOUT
        self.user_agent = config.USER_AGENT
        self.headers = {'User-Agent': self.user_agent}
    
    def crawl(self, start_url):
        """
        Crawl a website starting from the given URL up to a certain depth
        and respecting the maximum number of URLs to scan.
        """
        if not validators.url(start_url):
            return [], {"error": "Invalid URL provided"}
        
        visited = set()
        to_visit = [(start_url, 0)]  
        found_urls = []
        page_contents = {}
        
        ext = tldextract.extract(start_url)
        base_domain = f"{ext.domain}.{ext.suffix}"
        
        while to_visit and len(visited) < self.max_urls:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > self.max_depth:
                continue
                
            
            current_ext = tldextract.extract(current_url)
            current_domain = f"{current_ext.domain}.{current_ext.suffix}"
            if current_domain != base_domain:
                continue
            
            visited.add(current_url)
            found_urls.append(current_url)
            
            try:
                logger.info(f"Crawling: {current_url}")
                response = requests.get(
                    current_url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                
                if response.status_code != 200:
                    continue
                
                
                page_contents[current_url] = response.text
                
                if depth >= self.max_depth:
                    continue
                
                
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link['href']
                    if not href or href.startswith('#') or href.startswith('javascript:'):
                        continue
                    
                    
                    absolute_url = urllib.parse.urljoin(current_url, href)
                    
                    
                    if not validators.url(absolute_url):
                        continue
                    
                    
                    if absolute_url not in visited:
                        to_visit.append((absolute_url, depth + 1))
                
                
                time.sleep(0.5)
                
            except RequestException as e:
                logger.error(f"Error crawling {current_url}: {str(e)}")
                continue
        
        return found_urls, page_contents
    
    def fetch_page(self, url):
        """
        Fetch a single page and return its content.
        """
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.text, response.headers
            else:
                return None, None
        except RequestException as e:
            logger.error(f"Error fetching {url}: {str(e)}")
            return None, None