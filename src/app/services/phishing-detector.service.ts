// src/app/services/phishing-detector.service.ts

import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, of, delay } from 'rxjs';
import { catchError, retry, timeout } from 'rxjs/operators';
import { AnalysisResult, Finding, URLFeatures } from '../models/phishing.models';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class PhishingDetectorService {
  private readonly http = inject(HttpClient);

  // ========== CONFIGURATION (from environment) ==========
  private readonly apiUrl = environment.apiUrl;
  private readonly useMock = environment.useMock;
  private readonly timeoutMs = environment.production ? 60000 : 10000; // 60s prod, 10s local
  // ======================================================

  /**
   * Analyze a URL for phishing indicators
   */
  analyzeUrl(url: string, deepScan: boolean = false): Observable<AnalysisResult> {
    // Use mock engine if enabled
    if (this.useMock) {
      return this.mockAnalyze(url, deepScan);
    }

    // Use real API (local or production based on environment)
    return this.http.post<AnalysisResult>(`${this.apiUrl}/analyze`, {
      url,
      deep_scan: deepScan
    }).pipe(
      timeout(this.timeoutMs),
      retry(1),
      catchError((error: HttpErrorResponse) => this.handleAnalysisError(error, url))
    );
  }

  /**
   * Health check
   */
  healthCheck(): Observable<{ status: string; version: string }> {
    if (this.useMock) {
      return of({ status: 'healthy', version: '2.0.0 (Mock)' }).pipe(delay(300));
    }

    const healthUrl = this.apiUrl.replace('/api', '') + '/health';
    return this.http.get<{ status: string; version: string }>(healthUrl).pipe(
      timeout(10000),
      catchError(() => of({ status: 'offline', version: 'unknown' }))
    );
  }

  // ==================== MOCK ANALYSIS ENGINE ====================
  // Used when environment.useMock = true (for testing without any backend)

  private mockAnalyze(url: string, deepScan: boolean): Observable<AnalysisResult> {
    const startTime = performance.now();

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
    const features = this.extractFeatures(url, normalizedUrl, hostname);
    const isTrusted = this.isTrustedDomain(hostname);

    const addFinding = (level: Finding['level'], category: string, message: string, score: number, details?: string) => {
      findings.push({ level, category, message, score_impact: score, details });
      riskScore += score;
    };

    // === Security Checks ===

    // IP address check
    if (features.has_ip) {
      addFinding('danger', 'Structure', 'Uses IP address instead of domain name', 30,
        'Legitimate sites rarely use raw IP addresses');
    }

    // Suspicious TLD check
    const suspiciousTlds: Record<string, number> = {
      'tk': 25, 'ml': 25, 'ga': 25, 'cf': 25, 'gq': 25,
      'xyz': 15, 'top': 15, 'click': 20, 'link': 15, 'buzz': 15
    };
    const tld = hostname.split('.').pop() || '';
    if (suspiciousTlds[tld]) {
      addFinding('warning', 'Domain', `Uses high-risk TLD (.${tld})`, suspiciousTlds[tld],
        'This TLD is frequently abused for phishing');
    }

    // Subdomain check
    if (features.num_subdomains > 3) {
      addFinding('danger', 'Structure', `Excessive subdomains (${features.num_subdomains + 2} levels)`, 20,
        'Often used to hide the real domain');
    } else if (features.num_subdomains > 2) {
      addFinding('warning', 'Structure', `Multiple subdomains (${features.num_subdomains + 2} levels)`, 10);
    }

    // Brand impersonation check
    const brands = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix', 'bank', 'secure', 'login'];
    if (!isTrusted) {
      for (const brand of brands) {
        if (hostname.includes(brand)) {
          addFinding('critical', 'Impersonation', `Contains "${brand}" but is not official domain`, 35,
            `This may be impersonating ${brand}`);
          break;
        }
      }
    }

    // Typosquatting check (fixed - no regex global flag issue)
    const typoPatterns: [string, string][] = [['0', 'o'], ['1', 'l'], ['rn', 'm'], ['vv', 'w']];
    for (const [pattern, replacement] of typoPatterns) {
      if (hostname.includes(pattern)) {
        const normalized = hostname.split(pattern).join(replacement);
        if (this.isTrustedDomain(normalized) || brands.some(b => normalized.includes(b))) {
          addFinding('critical', 'Typosquatting', 'Possible typosquatting attack detected', 40,
            'Domain may be mimicking a legitimate site');
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

    // Deep scan simulation
    if (deepScan) {
      addFinding('info', 'DeepScan', 'Deep scan completed', 0,
        'WHOIS, DNS, and SSL checks simulated');
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

    // Calculate final score and level
    riskScore = Math.max(0, Math.min(100, riskScore));
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    if (riskScore >= 60) riskLevel = 'CRITICAL';
    else if (riskScore >= 40) riskLevel = 'HIGH';
    else if (riskScore >= 20) riskLevel = 'MEDIUM';
    else riskLevel = 'LOW';

    const analysisTime = performance.now() - startTime;

    return of({
      url,
      normalized_url: normalizedUrl,
      hostname,
      is_trusted: isTrusted,
      risk_score: riskScore,
      risk_level: riskLevel,
      findings,
      features,
      analysis_time_ms: Math.round(analysisTime)
    }).pipe(delay(500 + Math.random() * 300));
  }

  // ==================== HELPER METHODS ====================

  private extractFeatures(url: string, normalizedUrl: string, hostname: string): URLFeatures {
    let parsed: URL;
    try {
      parsed = new URL(normalizedUrl);
    } catch {
      return this.emptyFeatures();
    }

    const numDigits = (url.match(/\d/g) || []).length;
    const alphaCount = (url.match(/[a-zA-Z]/g) || []).length;
    const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
    const words = hostname.match(/[a-zA-Z]+/g) || [];

    return {
      url_length: url.length,
      hostname_length: hostname.length,
      path_length: parsed.pathname.length,
      query_length: parsed.search.length,
      num_dots: (url.match(/\./g) || []).length,
      num_hyphens: (url.match(/-/g) || []).length,
      num_underscores: (url.match(/_/g) || []).length,
      num_slashes: (url.match(/\//g) || []).length,
      num_digits: numDigits,
      num_params: parsed.searchParams.size,
      num_fragments: parsed.hash ? 1 : 0,
      num_subdomains: Math.max(0, hostname.split('.').length - 2),
      has_ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname),
      has_port: !!parsed.port,
      has_https: parsed.protocol === 'https:',
      has_at_symbol: url.includes('@'),
      has_double_slash: parsed.pathname.includes('//'),
      has_punycode: hostname.includes('xn--'),
      domain_entropy: this.calculateEntropy(hostname),
      path_entropy: this.calculateEntropy(parsed.pathname),
      digit_letter_ratio: numDigits / Math.max(alphaCount, 1),
      special_char_ratio: specialChars / Math.max(url.length, 1),
      is_shortened: this.isUrlShortener(hostname),
      tld_length: hostname.split('.').pop()?.length || 0,
      longest_word_length: Math.max(...words.map(w => w.length), 0),
      avg_word_length: words.length ? words.reduce((a, w) => a + w.length, 0) / words.length : 0
    };
  }

  private calculateEntropy(str: string): number {
    if (!str) return 0;
    const freq: Record<string, number> = {};
    for (const char of str) freq[char] = (freq[char] || 0) + 1;
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
      url, normalized_url: url, hostname: '', is_trusted: false,
      risk_score: 0, risk_level: 'LOW', findings: [],
      features: this.emptyFeatures(), analysis_time_ms: 0, error
    };
  }

  private handleAnalysisError(error: HttpErrorResponse, url: string): Observable<AnalysisResult> {
    let errorMessage: string;

    if (error.error instanceof ErrorEvent) {
      errorMessage = `Client error: ${error.error.message}`;
    } else if (error.status === 0) {
      errorMessage = environment.production
        ? 'Server is starting up (~30s). Please try again.'
        : 'Cannot connect to local backend. Is it running on localhost:8000?';
    } else if (error.status === 400) {
      errorMessage = error.error?.detail || 'Invalid URL format';
    } else if (error.status >= 500) {
      errorMessage = 'Server error. Please try again later.';
    } else {
      errorMessage = `Error ${error.status}: ${error.error?.detail || error.message}`;
    }

    return of(this.createErrorResult(url, errorMessage));
  }
}