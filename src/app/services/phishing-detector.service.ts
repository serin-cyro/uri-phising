// src/app/services/phishing-detector.service.ts
// Replace your current service with this mock version for testing

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, delay } from 'rxjs';
import { AnalysisResult, Finding, URLFeatures } from '../models/phishing.models';

@Injectable({
  providedIn: 'root'
})
export class PhishingDetectorService {
  private readonly http = inject(HttpClient);
  
  // Set to true to use mock data, false to use real API
  private readonly useMock = true;
  private readonly apiUrl = 'http://localhost:8000/api';

  analyzeUrl(url: string, deepScan: boolean = false): Observable<AnalysisResult> {
    if (this.useMock) {
      return this.mockAnalyze(url, deepScan);
    }
    // Real API call would go here
    return this.http.post<AnalysisResult>(`${this.apiUrl}/analyze`, { url, deep_scan: deepScan });
  }

  healthCheck(): Observable<{ status: string; version: string }> {
    if (this.useMock) {
      return of({ status: 'healthy', version: '2.0.0 (Mock)' }).pipe(delay(300));
    }
    return this.http.get<{ status: string; version: string }>(`${this.apiUrl.replace('/api', '')}/health`);
  }

  // ============== MOCK ANALYSIS ENGINE ==============
  private mockAnalyze(url: string, deepScan: boolean): Observable<AnalysisResult> {
    const startTime = performance.now();
    
    // Normalize URL
    let normalizedUrl = url.trim();
    if (!normalizedUrl.match(/^https?:\/\//i)) {
      normalizedUrl = 'http://' + normalizedUrl;
    }

    let hostname = '';
    try {
      const parsed = new URL(normalizedUrl);
      hostname = parsed.hostname.toLowerCase();
    } catch {
      return of(this.createErrorResult(url, 'Invalid URL format')).pipe(delay(500));
    }

    const findings: Finding[] = [];
    let riskScore = 0;

    // Extract features
    const features = this.extractFeatures(url, normalizedUrl, hostname);

    // Run checks
    const checks = this.runSecurityChecks(url, normalizedUrl, hostname, features, deepScan);
    findings.push(...checks.findings);
    riskScore = checks.riskScore;

    // Determine risk level
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    if (riskScore >= 60) riskLevel = 'CRITICAL';
    else if (riskScore >= 40) riskLevel = 'HIGH';
    else if (riskScore >= 20) riskLevel = 'MEDIUM';
    else riskLevel = 'LOW';

    // Clamp score
    riskScore = Math.max(0, Math.min(100, riskScore));

    const analysisTime = performance.now() - startTime;

    const result: AnalysisResult = {
      url,
      normalized_url: normalizedUrl,
      hostname,
      is_trusted: this.isTrustedDomain(hostname),
      risk_score: riskScore,
      risk_level: riskLevel,
      findings,
      features,
      analysis_time_ms: Math.round(analysisTime)
    };

    // Simulate network delay
    return of(result).pipe(delay(800 + Math.random() * 400));
  }

  private extractFeatures(url: string, normalizedUrl: string, hostname: string): URLFeatures {
    let parsed: URL;
    try {
      parsed = new URL(normalizedUrl);
    } catch {
      return this.emptyFeatures();
    }

    const urlLength = url.length;
    const hostnameLength = hostname.length;
    const pathLength = parsed.pathname.length;
    const queryLength = parsed.search.length;
    const numDots = (url.match(/\./g) || []).length;
    const numHyphens = (url.match(/-/g) || []).length;
    const numUnderscores = (url.match(/_/g) || []).length;
    const numSlashes = (url.match(/\//g) || []).length;
    const numDigits = (url.match(/\d/g) || []).length;
    const numParams = parsed.searchParams.size;
    const numFragments = parsed.hash ? 1 : 0;
    const numSubdomains = hostname.split('.').length - 2;
    const hasIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const hasPort = !!parsed.port;
    const hasHttps = parsed.protocol === 'https:';
    const hasAtSymbol = url.includes('@');
    const hasDoubleSlash = parsed.pathname.includes('//');
    const hasPunycode = hostname.includes('xn--');
    const domainEntropy = this.calculateEntropy(hostname);
    const pathEntropy = this.calculateEntropy(parsed.pathname);
    const alphaCount = (url.match(/[a-zA-Z]/g) || []).length;
    const digitLetterRatio = numDigits / Math.max(alphaCount, 1);
    const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
    const specialCharRatio = specialChars / Math.max(url.length, 1);
    const isShortened = this.isUrlShortener(hostname);
    const tldLength = hostname.split('.').pop()?.length || 0;
    const words = hostname.match(/[a-zA-Z]+/g) || [];
    const longestWordLength = Math.max(...words.map(w => w.length), 0);
    const avgWordLength = words.length ? words.reduce((a, w) => a + w.length, 0) / words.length : 0;

    return {
      url_length: urlLength,
      hostname_length: hostnameLength,
      path_length: pathLength,
      query_length: queryLength,
      num_dots: numDots,
      num_hyphens: numHyphens,
      num_underscores: numUnderscores,
      num_slashes: numSlashes,
      num_digits: numDigits,
      num_params: numParams,
      num_fragments: numFragments,
      num_subdomains: numSubdomains,
      has_ip: hasIp,
      has_port: hasPort,
      has_https: hasHttps,
      has_at_symbol: hasAtSymbol,
      has_double_slash: hasDoubleSlash,
      has_punycode: hasPunycode,
      domain_entropy: domainEntropy,
      path_entropy: pathEntropy,
      digit_letter_ratio: digitLetterRatio,
      special_char_ratio: specialCharRatio,
      is_shortened: isShortened,
      tld_length: tldLength,
      longest_word_length: longestWordLength,
      avg_word_length: avgWordLength
    };
  }

  private runSecurityChecks(
    url: string, 
    normalizedUrl: string, 
    hostname: string, 
    features: URLFeatures,
    deepScan: boolean
  ): { findings: Finding[]; riskScore: number } {
    const findings: Finding[] = [];
    let riskScore = 0;

    const addFinding = (level: Finding['level'], category: string, message: string, score: number, details?: string) => {
      findings.push({ level, category, message, score_impact: score, details });
      riskScore += score;
    };

    // Check IP address
    if (features.has_ip) {
      addFinding('danger', 'Structure', 'Uses IP address instead of domain name', 30, 
        'Legitimate sites rarely use raw IP addresses');
    }

    // Check suspicious TLDs
    const suspiciousTlds: Record<string, number> = {
      'tk': 25, 'ml': 25, 'ga': 25, 'cf': 25, 'gq': 25,
      'xyz': 15, 'top': 15, 'click': 20, 'link': 15, 'buzz': 15
    };
    const tld = hostname.split('.').pop() || '';
    if (suspiciousTlds[tld]) {
      addFinding('warning', 'Domain', `Uses high-risk TLD (.${tld})`, suspiciousTlds[tld],
        'This TLD is frequently abused for phishing');
    }

    // Check subdomains
    if (features.num_subdomains > 3) {
      addFinding('danger', 'Structure', `Excessive subdomains (${features.num_subdomains + 2} levels)`, 20,
        'Often used to hide the real domain');
    } else if (features.num_subdomains > 2) {
      addFinding('warning', 'Structure', `Multiple subdomains (${features.num_subdomains + 2} levels)`, 10);
    }

    // Check brand impersonation
    const brands = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix', 'bank', 'secure', 'login'];
    const isTrusted = this.isTrustedDomain(hostname);
    
    if (!isTrusted) {
      for (const brand of brands) {
        if (hostname.includes(brand)) {
          addFinding('critical', 'Impersonation', `Contains "${brand}" but is not official domain`, 35,
            `This may be impersonating ${brand}`);
          break;
        }
      }
    }

    // Check typosquatting (number substitutions)
    const typoChecks = [
      { pattern: /0/g, replacement: 'o' },
      { pattern: /1/g, replacement: 'l' },
      { pattern: /rn/g, replacement: 'm' },
      { pattern: /vv/g, replacement: 'w' }
    ];
    
    for (const check of typoChecks) {
      if (check.pattern.test(hostname)) {
        const normalized = hostname.replace(check.pattern, check.replacement);
        if (this.isTrustedDomain(normalized) || brands.some(b => normalized.includes(b))) {
          addFinding('critical', 'Typosquatting', 'Possible typosquatting attack detected', 40,
            `Domain may be mimicking a legitimate site`);
          break;
        }
      }
    }

    // Check @ symbol (URL obfuscation)
    if (features.has_at_symbol) {
      addFinding('critical', 'Obfuscation', 'Contains @ symbol in URL', 40,
        'Can trick users about actual destination');
    }

    // Check punycode
    if (features.has_punycode) {
      addFinding('warning', 'Encoding', 'Uses Punycode (internationalized domain)', 20,
        'May be legitimate or homograph attack');
    }

    // Check entropy
    if (features.domain_entropy > 4.0) {
      addFinding('warning', 'Randomness', `High domain entropy (${features.domain_entropy.toFixed(2)})`, 15,
        'May indicate randomly generated domain');
    }

    // Check URL length
    if (features.url_length > 200) {
      addFinding('warning', 'Length', `Very long URL (${features.url_length} chars)`, 15,
        'Excessive length may hide malicious content');
    } else if (features.url_length > 100) {
      addFinding('info', 'Length', `Long URL (${features.url_length} chars)`, 5);
    }

    // Check suspicious path keywords
    const sensitiveKeywords = ['login', 'signin', 'password', 'verify', 'secure', 'account', 'update', 'banking'];
    const path = new URL(normalizedUrl).pathname.toLowerCase();
    
    if (!isTrusted) {
      for (const keyword of sensitiveKeywords) {
        if (path.includes(keyword)) {
          addFinding('danger', 'Path', `Contains sensitive keyword "${keyword}"`, 20,
            'Combined with untrusted domain, this is suspicious');
          break;
        }
      }
    }

    // Check protocol
    if (!features.has_https) {
      addFinding('warning', 'Security', 'Uses insecure HTTP connection', 10,
        'Legitimate login pages use HTTPS');
    }

    // Check URL shortener
    if (features.is_shortened) {
      addFinding('warning', 'Shortener', 'URL shortener detected', 15,
        'Destination URL is hidden');
    }

    // Check redirect params
    const redirectParams = ['url', 'redirect', 'next', 'return', 'goto', 'dest'];
    const searchParams = new URL(normalizedUrl).searchParams;
    for (const param of redirectParams) {
      if (searchParams.has(param)) {
        addFinding('warning', 'Redirect', `Contains redirect parameter "${param}"`, 15,
          'May be used for open redirect attacks');
        break;
      }
    }

    // Deep scan extras
    if (deepScan) {
      addFinding('info', 'DeepScan', 'Deep scan completed', 0,
        'WHOIS, DNS, and SSL checks simulated');
      
      // Simulate finding new domain
      if (Math.random() > 0.7 && !isTrusted) {
        addFinding('warning', 'WHOIS', 'Domain registered recently (simulated)', 15,
          'Newly registered domains are often suspicious');
      }
    }

    // Positive indicators
    if (isTrusted) {
      addFinding('safe', 'Trust', 'Verified trusted domain', -50,
        'Domain matches known legitimate site');
    }

    if (features.has_https && !findings.some(f => f.level === 'critical' || f.level === 'danger')) {
      addFinding('safe', 'Security', 'Uses HTTPS encryption', -5);
    }

    return { findings, riskScore };
  }

  private calculateEntropy(str: string): number {
    if (!str) return 0;
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  }

  private isTrustedDomain(hostname: string): boolean {
    const trusted = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
      'paypal.com', 'netflix.com', 'github.com', 'linkedin.com', 'twitter.com',
      'instagram.com', 'dropbox.com', 'chase.com', 'bankofamerica.com'
    ];
    return trusted.some(d => hostname === d || hostname.endsWith('.' + d));
  }

  private isUrlShortener(hostname: string): boolean {
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
    return shorteners.some(s => hostname.includes(s));
  }

  private emptyFeatures(): URLFeatures {
    return {
      url_length: 0, hostname_length: 0, path_length: 0, query_length: 0,
      num_dots: 0, num_hyphens: 0, num_underscores: 0, num_slashes: 0,
      num_digits: 0, num_params: 0, num_fragments: 0, num_subdomains: 0,
      has_ip: false, has_port: false, has_https: false, has_at_symbol: false,
      has_double_slash: false, has_punycode: false, domain_entropy: 0,
      path_entropy: 0, digit_letter_ratio: 0, special_char_ratio: 0,
      is_shortened: false, tld_length: 0, longest_word_length: 0, avg_word_length: 0
    };
  }

  private createErrorResult(url: string, error: string): AnalysisResult {
    return {
      url,
      normalized_url: url,
      hostname: '',
      is_trusted: false,
      risk_score: 0,
      risk_level: 'LOW',
      findings: [],
      features: this.emptyFeatures(),
      analysis_time_ms: 0,
      error
    };
  }
}