import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime
import whois
import dns.resolver
from Levenshtein import distance as levenshtein_distance
import tldextract
import pandas as pd
import numpy as np
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

class PhishingFeatureExtractor:
    """
    A comprehensive feature extractor for phishing detection that analyzes URLs and HTML content
    to generate features useful for machine learning models.
    """
    
    def __init__(self):
        """Initialize the feature extractor with necessary configurations."""
        self.short_url_services = [
            'bit\.ly', 'goo\.gl', 'shorte\.st', 'go2l\.ink', 'x\.co', 'ow\.ly', 
            't\.co', 'tinyurl', 'tr\.im', 'is\.gd', 'cli\.gs', 'yfrog\.com', 
            'migre\.me', 'ff\.im', 'tiny\.cc', 'url4\.eu', 'twit\.ac', 'su\.pr', 
            'twurl\.nl', 'snipurl\.com', 'short\.to', 'budurl\.com', 'ping\.fm', 
            'post\.ly', 'just\.as', 'bkite\.com', 'snipr\.com', 'fic\.kr', 'loopt\.us', 
            'doiop\.com', 'short\.ie', 'kl\.am', 'wp\.me', 'rubyurl\.com', 'om\.ly', 
            'to\.ly', 'bit\.do', 'lnkd\.in', 'db\.tt', 'qr\.ae', 'adf\.ly', 'bitly\.com', 
            'cur\.lv', 'tinyurl\.com', 'ity\.im', 'q\.gs', 'po\.st', 'bc\.vc', 
            'twitthis\.com', 'u\.to', 'j\.mp', 'buzurl\.com', 'cutt\.us', 'u\.bb', 
            'yourls\.org', 'prettylinkpro\.com', 'scrnch\.me', 'filoops\.info', 
            'vzturl\.com', 'qr\.net', '1url\.com', 'tweez\.me', 'v\.gd', 'link\.zip\.net'
        ]
        
        self.stop_words = set(stopwords.words('english'))
        self.browser_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def extract_features(self, url, html_content=None, fetch_online=False):
        """
        Extract all features from a URL and optional HTML content.
        
        Args:
            url (str): The URL to analyze
            html_content (str): Optional pre-fetched HTML content
            fetch_online (bool): Whether to fetch content online if html_content is not provided
            
        Returns:
            dict: Dictionary containing all extracted features
        """
        features = {}
        
        # Parse URL components
        parsed_url = urlparse(url)
        
        # Extract URL-based features
        features.update(self._extract_url_features(url, parsed_url))
        
        # Fetch HTML if needed
        soup = None
        if html_content:
            soup = BeautifulSoup(html_content, 'lxml')
        elif fetch_online:
            try:
                response = requests.get(url, headers=self.browser_headers, timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'lxml')
            except:
                pass
        
        # Extract HTML-based features if soup is available
        if soup:
            features.update(self._extract_html_features(soup, url, parsed_url))
        
        # Extract domain-based features
        features.update(self._extract_domain_features(url, parsed_url))
        
        return features
    
    def _extract_url_features(self, url, parsed_url):
        """Extract features based on URL structure."""
        features = {}
        
        # URL length features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        
        # Subdomain analysis
        domain_parts = parsed_url.netloc.split('.')
        features['subdomain_count'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
        
        # Check for IP address
        features['is_ip_address'] = self._is_ip_address(parsed_url.netloc)
        
        # URL encoding and special characters
        features['percent_encoded_chars'] = url.count('%')
        features['special_char_count'] = sum(url.count(c) for c in ['@', '?', '=', '_', '&', '~', '-'])
        
        # Redirection check
        features['has_internal_redirects'] = url.count('//') > 1
        
        # Short URL service check
        features['is_short_url'] = self._is_short_url(url)
        
        # Hyphen and underscore in domain
        features['domain_has_hyphen'] = '-' in parsed_url.netloc
        features['domain_has_underscore'] = '_' in parsed_url.netloc
        
        # Protocol features
        features['uses_https'] = parsed_url.scheme == 'https'
        
        # Digits in URL components
        features['digits_in_domain'] = sum(c.isdigit() for c in parsed_url.netloc)
        features['digits_in_path'] = sum(c.isdigit() for c in parsed_url.path)
        
        return features
    
    def _extract_html_features(self, soup, url, parsed_url):
        """Extract features from HTML content."""
        features = {}
        
        # Page content features
        features['page_text_length'] = len(soup.get_text())
        features['has_title'] = bool(soup.title)
        features['title_length'] = len(soup.title.string) if soup.title else 0
        
        # Meta tags analysis
        meta_tags = soup.find_all('meta')
        features['meta_tag_count'] = len(meta_tags)
        features['has_description_meta'] = any(tag.get('name') == 'description' for tag in meta_tags)
        features['has_keywords_meta'] = any(tag.get('name') == 'keywords' for tag in meta_tags)
        
        # Form analysis
        forms = soup.find_all('form')
        features['form_count'] = len(forms)
        features['has_password_input'] = bool(soup.find('input', {'type': 'password'}))
        
        # Iframe analysis
        iframes = soup.find_all('iframe')
        features['iframe_count'] = len(iframes)
        features['has_external_iframe'] = self._has_external_iframe(iframes, url, parsed_url)
        
        # Link analysis
        links = soup.find_all('a', href=True)
        if links:
            link_analysis = self._analyze_links(links, url, parsed_url)
            features.update(link_analysis)
        
        # Image analysis
        images = soup.find_all('img', src=True)
        if images:
            image_analysis = self._analyze_images(images, url, parsed_url)
            features.update(image_analysis)
        
        # Script analysis
        scripts = soup.find_all('script', src=True)
        if scripts:
            script_analysis = self._analyze_scripts(scripts, url, parsed_url)
            features.update(script_analysis)
        
        # Copyright and branding
        page_text = soup.get_text().lower()
        features['has_copyright'] = bool(re.search(r'copyright|©', page_text))
        
        # Favicon analysis
        features['has_favicon'] = self._check_favicon(soup, url, parsed_url)
        
        return features
    
    def _extract_domain_features(self, url, parsed_url):
        """Extract features related to domain properties."""
        features = {}
        
        # Domain name analysis
        extracted = tldextract.extract(url)
        features['tld'] = extracted.suffix
        features['is_common_tld'] = extracted.suffix in ['com', 'org', 'net', 'edu', 'gov', 'mil']
        
        # Try to get domain registration info
        try:
            domain_info = whois.whois(parsed_url.netloc)
            if domain_info:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    domain_age = (datetime.now() - creation_date).days
                    features['domain_age_days'] = domain_age
                    features['domain_age_years'] = domain_age / 365.0
        except:
            features['domain_age_days'] = -1
            features['domain_age_years'] = -1
        
        # Check SSL certificate
        features['has_valid_ssl'] = self._check_ssl(parsed_url.netloc)
        
        # DNS resolution check
        features['dns_resolvable'] = self._check_dns(parsed_url.netloc)
        
        return features
    
    def _analyze_links(self, links, url, parsed_url):
        """Analyze anchor tags and their hrefs."""
        features = {}
        total_links = len(links)
        internal_links = 0
        external_links = 0
        suspicious_links = 0
        ssl_links = 0
        
        for link in links:
            href = link.get('href', '')
            
            # Link classification
            if href.startswith('#') or href == '':
                # In-page link
                continue
            elif href.startswith('mailto:') or href.startswith('javascript:'):
                suspicious_links += 1
            elif href.startswith('https://'):
                ssl_links += 1
                
            # Internal vs external
            if self._is_internal_link(href, url, parsed_url):
                internal_links += 1
            else:
                external_links += 1
        
        # Calculate ratios
        if total_links > 0:
            features['internal_links_ratio'] = internal_links / total_links
            features['external_links_ratio'] = external_links / total_links
            features['suspicious_links_ratio'] = suspicious_links / total_links
            features['ssl_links_ratio'] = ssl_links / total_links
        else:
            features['internal_links_ratio'] = 0
            features['external_links_ratio'] = 0
            features['suspicious_links_ratio'] = 0
            features['ssl_links_ratio'] = 0
        
        return features
    
    def _analyze_images(self, images, url, parsed_url):
        """Analyze image sources and their properties."""
        features = {}
        total_images = len(images)
        internal_images = 0
        external_images = 0
        ssl_images = 0
        
        for img in images:
            src = img.get('src', '')
            
            if src.startswith('https://'):
                ssl_images += 1
            
            if self._is_internal_link(src, url, parsed_url):
                internal_images += 1
            else:
                external_images += 1
        
        # Calculate ratios
        if total_images > 0:
            features['internal_images_ratio'] = internal_images / total_images
            features['external_images_ratio'] = external_images / total_images
            features['ssl_images_ratio'] = ssl_images / total_images
        else:
            features['internal_images_ratio'] = 0
            features['external_images_ratio'] = 0
            features['ssl_images_ratio'] = 0
        
        features['total_images'] = total_images
        
        return features
    
    def _analyze_scripts(self, scripts, url, parsed_url):
        """Analyze script sources and their properties."""
        features = {}
        total_scripts = len(scripts)
        internal_scripts = 0
        external_scripts = 0
        ssl_scripts = 0
        
        for script in scripts:
            src = script.get('src', '')
            
            if src.startswith('https://'):
                ssl_scripts += 1
            
            if self._is_internal_link(src, url, parsed_url):
                internal_scripts += 1
            else:
                external_scripts += 1
        
        # Calculate ratios
        if total_scripts > 0:
            features['internal_scripts_ratio'] = internal_scripts / total_scripts
            features['external_scripts_ratio'] = external_scripts / total_scripts
            features['ssl_scripts_ratio'] = ssl_scripts / total_scripts
        else:
            features['internal_scripts_ratio'] = 0
            features['external_scripts_ratio'] = 0
            features['ssl_scripts_ratio'] = 0
        
        features['total_scripts'] = total_scripts
        
        return features
    
    def _is_ip_address(self, domain):
        """Check if the domain is an IP address."""
        try:
            ipaddress.ip_address(domain)
            return 1
        except:
            return 0
    
    def _is_short_url(self, url):
        """Check if URL uses a URL shortening service."""
        pattern = '|'.join(self.short_url_services)
        return 1 if re.search(pattern, url) else 0
    
    def _is_internal_link(self, link, url, parsed_url):
        """Determine if a link is internal to the domain."""
        if link.startswith('/') or link.startswith('./'):
            return True
        
        parsed_link = urlparse(link)
        return parsed_link.netloc == '' or parsed_link.netloc == parsed_url.netloc
    
    def _check_ssl(self, domain):
        """Check if domain has valid SSL certificate."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return 1
        except:
            return 0
    
    def _check_dns(self, domain):
        """Check if domain is DNS resolvable."""
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return 0
    
    def _check_favicon(self, soup, url, parsed_url):
        """Check for presence of favicon."""
        favicon_links = soup.find_all('link', rel=lambda x: x and 'icon' in x.lower())
        
        for link in favicon_links:
            href = link.get('href', '')
            if self._is_internal_link(href, url, parsed_url):
                return 1
        
        return 0
    
    def _has_external_iframe(self, iframes, url, parsed_url):
        """Check if page contains external iframes."""
        for iframe in iframes:
            src = iframe.get('src', '')
            if not self._is_internal_link(src, url, parsed_url):
                return 1
        return 0


# Example usage
if __name__ == "__main__":
    # Initialize extractor
    extractor = PhishingFeatureExtractor()
    
    # Extract features from a URL
    url = "https://example.com"
    features = extractor.extract_features(url, fetch_online=True)
    
    # Print feature names and values
    for feature_name, value in features.items():
        print(f"{feature_name}: {value}")
