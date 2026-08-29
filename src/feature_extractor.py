import re
from urllib.parse import urlparse
import tldextract

class URLLexicalFeatureExtractor:
    def __init__(self):
        # Daftar kata kunci yang sering muncul pada URL Phishing
        self.suspicious_words = [
            'login', 'verify', 'update', 'account', 'banking', 'secure',
            'confirm', 'service', 'signin', 'support', 'wallet', 'admin'
        ]

    def extract_features(self, url: str) -> dict:
        if not isinstance(url, str):
            url = str(url) if url is not None else ""
            
        url = url.strip()
        
        # Format Scheme
        if not url.startswith(('http://', 'https://')):
            parse_url = 'http://' + url
        else:
            parse_url = url

        # Sanitasi URL untuk cegah error IPv6
        safe_url = parse_url.replace('[', '').replace(']', '')

        domain, subdomain, suffix, hostname, path = "", "", "", "", ""

        try:
            parsed = urlparse(safe_url)
            hostname = parsed.netloc or ""
            path = parsed.path or ""
        except Exception:
            pass

        try:
            ext = tldextract.extract(safe_url)
            domain = ext.domain or ""
            subdomain = ext.subdomain or ""
            suffix = ext.suffix or ""
        except Exception:
            pass

        url_lower = url.lower()
        url_len = max(len(url), 1)

        # Hitung kalkulasi karakter sekali di memori
        num_digits = sum(c.isdigit() for c in url)
        num_letters = sum(c.isalpha() for c in url)

        # Perbaikan bug split subdomain kosong
        subdomain_list = [s for s in subdomain.split('.') if s] if subdomain else []

        # Fitur Leksikal & Statistik
        features = {
            'url_length': len(url),
            'hostname_length': len(hostname),
            'path_length': len(path),
            'count_dots': url.count('.'),
            'count_hyphens': url.count('-'),
            'count_at': url.count('@'),
            'count_question': url.count('?'),
            'count_equal': url.count('='),
            'count_slash': url.count('/'),
            'count_percent': url.count('%'),
            'count_digits': num_digits,
            'count_letters': num_letters,
            'digit_ratio': num_digits / url_len,
            'has_ip': 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname) else 0,
            'is_https': 1 if url_lower.startswith('https://') else 0,
            'subdomain_count': len(subdomain_list),
            'has_subdomain': 1 if len(subdomain_list) > 0 else 0,
            'suspicious_keyword_count': sum(1 for word in self.suspicious_words if word in url_lower)
        }

        return features