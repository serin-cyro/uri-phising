# backend/phishing_detector.py

import re
import math
import string
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Dict, List, Tuple
from datetime import datetime
from collections import Counter

# Optional imports for deep scan
WHOIS_AVAILABLE = False  # Disabled for cloud deployment

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class PhishingDetector:
    """Advanced URL phishing detector."""
    
    SUSPICIOUS_TLDS: Dict[str, int] = {
        'tk': 25, 'ml': 25, 'ga': 25, 'cf': 25, 'gq': 25,
        'xyz': 15, 'top': 15, 'work': 15, 'click': 20, 'link': 15,
        'buzz': 15, 'icu': 20, 'surf': 15, 'rest': 15, 'fit': 10,
        'cam': 15, 'monster': 15, 'quest': 10, 'sbs': 20, 'cfd': 20
    }
    
    TRUSTED_DOMAINS: Dict[str, List[str]] = {
        'google.com': ['accounts', 'mail', 'drive', 'docs', 'www', 'support'],
        'microsoft.com': ['login', 'account', 'outlook', 'www', 'support', 'office'],
        'apple.com': ['www', 'support', 'id', 'icloud'],
        'amazon.com': ['www', 'aws', 'signin', 'pay'],
        'facebook.com': ['www', 'm', 'business'],
        'paypal.com': ['www', 'business'],
        'netflix.com': ['www'],
        'linkedin.com': ['www'],
        'twitter.com': ['www', 'mobile'],
        'instagram.com': ['www'],
        'github.com': ['www', 'gist', 'api'],
        'dropbox.com': ['www'],
        'chase.com': ['www', 'secure'],
        'bankofamerica.com': ['www', 'secure'],
        'wellsfargo.com': ['www', 'connect'],
    }
    
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'tiny.cc'
    }
    
    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
        'і': 'i', 'ј': 'j', '0': 'o', '1': 'l', '3': 'e', '5': 's',
    }
    
    SENSITIVE_KEYWORDS = {
        'high': ['login', 'signin', 'password', 'credential', 'auth', 'verify', 'banking'],
        'medium': ['account', 'secure', 'update', 'confirm', 'validate', 'wallet'],
        'low': ['user', 'profile', 'settings', 'admin']
    }
    
    TARGET_BRANDS = [
        'google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal',
        'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex'
    ]

    def __init__(self, url: str, deep_scan: bool = False):
        self.original_url = url.strip()
        self.url = self._normalize_url(self.original_url)
        self.deep_scan = deep_scan
        self.findings: List[Dict] = []
        self.risk_score = 0
        self.parsed = None
        self.features = {}
        self.hostname = ""
        self.is_trusted = False
        self.target_brand: Optional[str] = None
        self.threat_type: Optional[str] = None

    def _normalize_url(self, url: str) -> str:
        url = unquote(url)
        if not re.match(r'^https?://', url, re.I):
            return 'http://' + url
        return url

    def _add_finding(self, level: str, category: str, message: str, 
                     score: int, details: str = None):
        self.findings.append({
            'level': level,
            'category': category,
            'message': message,
            'score_impact': score,
            'details': details
        })
        self.risk_score += score

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) 
                       for count in counter.values())
        return round(entropy, 3)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _normalize_homoglyphs(self, text: str) -> str:
        result = text
        for homoglyph, ascii_char in self.HOMOGLYPHS.items():
            result = result.replace(homoglyph, ascii_char)
        return result

    def _is_trusted_domain(self, hostname: str) -> Tuple[bool, Optional[str]]:
        for domain, valid_subdomains in self.TRUSTED_DOMAINS.items():
            if hostname == domain:
                return True, domain
            if hostname.endswith('.' + domain):
                return True, domain
        return False, None

    def _extract_features(self):
        f = {}
        f['url_length'] = len(self.original_url)
        f['hostname_length'] = len(self.hostname)
        f['path_length'] = len(self.parsed.path)
        f['query_length'] = len(self.parsed.query)
        f['num_dots'] = self.original_url.count('.')
        f['num_hyphens'] = self.original_url.count('-')
        f['num_underscores'] = self.original_url.count('_')
        f['num_slashes'] = self.original_url.count('/')
        f['num_digits'] = sum(c.isdigit() for c in self.original_url)
        f['num_params'] = len(parse_qs(self.parsed.query))
        f['num_fragments'] = 1 if self.parsed.fragment else 0
        f['num_subdomains'] = max(0, len(self.hostname.split('.')) - 2)
        f['has_ip'] = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', self.hostname))
        f['has_port'] = bool(self.parsed.port)
        f['has_https'] = self.parsed.scheme == 'https'
        f['has_at_symbol'] = '@' in self.original_url
        f['has_double_slash'] = '//' in self.parsed.path
        f['has_punycode'] = 'xn--' in self.hostname
        f['domain_entropy'] = self._calculate_entropy(self.hostname)
        f['path_entropy'] = self._calculate_entropy(self.parsed.path)
        alpha = sum(c.isalpha() for c in self.original_url)
        f['digit_letter_ratio'] = f['num_digits'] / max(alpha, 1)
        special = sum(c in string.punctuation for c in self.original_url)
        f['special_char_ratio'] = special / max(len(self.original_url), 1)
        f['is_shortened'] = any(s in self.hostname for s in self.URL_SHORTENERS)
        parts = self.hostname.split('.')
        f['tld_length'] = len(parts[-1]) if parts else 0
        words = re.findall(r'[a-zA-Z]+', self.hostname)
        f['longest_word_length'] = max((len(w) for w in words), default=0)
        f['avg_word_length'] = sum(len(w) for w in words) / max(len(words), 1)
        self.features = f

    def _check_ip_address(self):
        if self.features['has_ip']:
            self._add_finding('danger', 'Structure',
                'Uses IP address instead of domain name', 30,
                'Legitimate sites rarely use raw IP addresses')
            self.threat_type = 'ip_based'

    def _check_suspicious_tld(self):
        tld = self.hostname.split('.')[-1].lower()
        if tld in self.SUSPICIOUS_TLDS:
            score = self.SUSPICIOUS_TLDS[tld]
            self._add_finding('warning', 'Domain',
                f'Uses high-risk TLD (.{tld})', score,
                'This TLD is frequently abused for phishing')

    def _check_subdomains(self):
        count = self.features['num_subdomains']
        if count > 3:
            self._add_finding('danger', 'Structure',
                f'Excessive subdomains ({count + 2} levels)', 20,
                'Often used to hide the real domain')
        elif count > 2:
            self._add_finding('warning', 'Structure',
                f'Multiple subdomains ({count + 2} levels)', 10)

    def _check_brand_impersonation(self):
        if self.is_trusted:
            return
        normalized = self._normalize_homoglyphs(self.hostname)
        for domain in self.TRUSTED_DOMAINS.keys():
            brand = domain.split('.')[0]
            if brand in self.hostname and brand not in ['pay', 'bank']:
                self._add_finding('critical', 'Impersonation',
                    f'Contains "{brand}" but is not official domain', 35,
                    f'Official domain is {domain}')
                self.target_brand = brand
                self.threat_type = 'brand_impersonation'
                return
            hostname_base = self.hostname.split('.')[0]
            distance = self._levenshtein_distance(hostname_base, brand)
            if 0 < distance <= 2 and len(hostname_base) >= len(brand) - 1:
                self._add_finding('critical', 'Typosquatting',
                    f'Domain "{hostname_base}" is similar to "{brand}"', 40,
                    f'Edit distance: {distance}')
                self.target_brand = brand
                self.threat_type = 'typosquatting'
                return

    def _check_homograph_attack(self):
        original = self.hostname
        normalized = self._normalize_homoglyphs(original)
        if original != normalized:
            self._add_finding('critical', 'Homograph',
                'Contains lookalike Unicode characters', 45,
                f'Normalized: {normalized}')
            self.threat_type = 'homograph'
            for domain in self.TRUSTED_DOMAINS.keys():
                if domain.split('.')[0] in normalized:
                    self.target_brand = domain.split('.')[0]
                    break

    def _check_url_obfuscation(self):
        if self.features['has_at_symbol']:
            self._add_finding('critical', 'Obfuscation',
                'Contains @ symbol in URL', 40,
                'Can trick users about actual destination')
            self.threat_type = 'obfuscation'
        if self.features['has_double_slash']:
            self._add_finding('warning', 'Obfuscation',
                'Contains double slash in path', 15)

    def _check_entropy(self):
        if self.features['domain_entropy'] > 4.0:
            self._add_finding('warning', 'Randomness',
                f"High domain entropy ({self.features['domain_entropy']})", 15,
                'May indicate randomly generated domain')

    def _check_url_length(self):
        length = self.features['url_length']
        if length > 200:
            self._add_finding('warning', 'Length',
                f'Very long URL ({length} chars)', 15)
        elif length > 100:
            self._add_finding('info', 'Length', f'Long URL ({length} chars)', 5)

    def _check_suspicious_path(self):
        if self.is_trusted:
            return
        path = self.parsed.path.lower()
        for level, keywords in self.SENSITIVE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in path:
                    if level == 'high':
                        self._add_finding('danger', 'Path',
                            f'Contains sensitive keyword "{keyword}"', 20)
                    elif level == 'medium':
                        self._add_finding('warning', 'Path',
                            f'Contains keyword "{keyword}"', 10)
                    return

    def _check_protocol(self):
        if not self.features['has_https']:
            self._add_finding('warning', 'Security',
                'Uses insecure HTTP connection', 10)

    def _check_url_shortener(self):
        if self.features['is_shortened']:
            self._add_finding('warning', 'Shortener',
                'URL shortener detected', 15, 'Destination URL is hidden')
            self.threat_type = 'shortened'

    def _check_punycode(self):
        if self.features['has_punycode']:
            self._add_finding('warning', 'Encoding',
                'Uses Punycode (internationalized domain)', 20)

    def _check_redirect_params(self):
        params = parse_qs(self.parsed.query.lower())
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'dest']
        for param in redirect_params:
            if param in params:
                self._add_finding('warning', 'Redirect',
                    f'Contains redirect parameter "{param}"', 15)
                break

    def _deep_scan_whois(self):
        if not WHOIS_AVAILABLE:
            return
        try:
            w = whois.whois(self.hostname)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    self._add_finding('danger', 'WHOIS',
                        f'Domain registered {age_days} days ago', 25)
                elif age_days < 90:
                    self._add_finding('warning', 'WHOIS',
                        f'Domain registered {age_days} days ago', 10)
        except Exception:
            pass

    def _deep_scan_dns(self):
        if not DNS_AVAILABLE:
            return
        try:
            answers = dns.resolver.resolve(self.hostname, 'A')
            if len(list(answers)) > 5:
                self._add_finding('warning', 'DNS',
                    'Multiple A records detected', 10,
                    'May indicate fast-flux hosting')
        except Exception:
            pass

    def analyze(self) -> dict:
        """Run full URL analysis and return results."""
        start_time = datetime.now()
        
        try:
            self.parsed = urlparse(self.url)
            self.hostname = (self.parsed.hostname or '').lower()
        except Exception:
            return {
                'url': self.original_url,
                'normalized_url': self.url,
                'hostname': '',
                'is_trusted': False,
                'risk_score': 0,
                'risk_level': 'LOW',
                'findings': [],
                'features': self._empty_features(),
                'analysis_time_ms': 0,
                'error': 'Invalid URL format'
            }

        if not self.hostname:
            return {
                'url': self.original_url,
                'normalized_url': self.url,
                'hostname': '',
                'is_trusted': False,
                'risk_score': 0,
                'risk_level': 'LOW',
                'findings': [],
                'features': self._empty_features(),
                'analysis_time_ms': 0,
                'error': 'Could not extract hostname'
            }

        self.is_trusted, _ = self._is_trusted_domain(self.hostname)
        self._extract_features()

        # Run all checks
        self._check_ip_address()
        self._check_suspicious_tld()
        self._check_subdomains()
        self._check_homograph_attack()
        self._check_punycode()
        self._check_brand_impersonation()
        self._check_url_obfuscation()
        self._check_entropy()
        self._check_url_length()
        self._check_suspicious_path()
        self._check_protocol()
        self._check_url_shortener()
        self._check_redirect_params()

        # Deep scan if enabled
        if self.deep_scan:
            self._deep_scan_whois()
            self._deep_scan_dns()

        # Positive indicators
        if self.is_trusted:
            self._add_finding('safe', 'Trust', 'Verified trusted domain', -50)
        
        if self.features['has_https'] and not any(
            f['level'] in ['critical', 'danger'] for f in self.findings
        ):
            self._add_finding('safe', 'Security', 'Uses HTTPS encryption', -5)

        # Clamp risk score
        self.risk_score = max(0, min(100, self.risk_score))

        # Determine risk level
        if self.risk_score >= 60:
            risk_level = 'CRITICAL'
        elif self.risk_score >= 40:
            risk_level = 'HIGH'
        elif self.risk_score >= 20:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        analysis_time = (datetime.now() - start_time).total_seconds() * 1000

        return {
            'url': self.original_url,
            'normalized_url': self.url,
            'hostname': self.hostname,
            'is_trusted': self.is_trusted,
            'risk_score': self.risk_score,
            'risk_level': risk_level,
            'findings': self.findings,
            'features': self.features,
            'analysis_time_ms': round(analysis_time, 2),
            'threat_type': self.threat_type,
            'target_brand': self.target_brand
        }

    def _empty_features(self) -> dict:
        return {
            'url_length': 0, 'hostname_length': 0, 'path_length': 0,
            'query_length': 0, 'num_dots': 0, 'num_hyphens': 0,
            'num_underscores': 0, 'num_slashes': 0, 'num_digits': 0,
            'num_params': 0, 'num_fragments': 0, 'num_subdomains': 0,
            'has_ip': False, 'has_port': False, 'has_https': False,
            'has_at_symbol': False, 'has_double_slash': False,
            'has_punycode': False, 'domain_entropy': 0.0,
            'path_entropy': 0.0, 'digit_letter_ratio': 0.0,
            'special_char_ratio': 0.0, 'is_shortened': False,
            'tld_length': 0, 'longest_word_length': 0, 'avg_word_length': 0.0
        }