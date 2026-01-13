// src/app/models/phishing.models.ts

export interface Finding {
    level: 'critical' | 'danger' | 'warning' | 'info' | 'safe';
    category: string;
    message: string;
    score_impact: number;
    details?: string;
}

export interface URLFeatures {
    url_length: number;
    hostname_length: number;
    path_length: number;
    query_length: number;
    num_dots: number;
    num_hyphens: number;
    num_underscores: number;
    num_slashes: number;
    num_digits: number;
    num_params: number;
    num_fragments: number;
    num_subdomains: number;
    has_ip: boolean;
    has_port: boolean;
    has_https: boolean;
    has_at_symbol: boolean;
    has_double_slash: boolean;
    has_punycode: boolean;
    domain_entropy: number;
    path_entropy: number;
    digit_letter_ratio: number;
    special_char_ratio: number;
    is_shortened: boolean;
    tld_length: number;
    longest_word_length: number;
    avg_word_length: number;
}

export interface AnalysisResult {
    url: string;
    normalized_url: string;
    hostname: string;
    is_trusted: boolean;
    risk_score: number;
    risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    findings: Finding[];
    features: URLFeatures;
    analysis_time_ms: number;
    error?: string;
}

export interface AnalysisHistory {
    id: string;
    result: AnalysisResult;
    timestamp: Date;
}

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const RISK_COLORS: Record<RiskLevel, string> = {
    CRITICAL: '#dc2626',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e'
};

export const RISK_ICONS: Record<RiskLevel, string> = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡',
    LOW: '🟢'
};

export const LEVEL_ICONS: Record<string, string> = {
    critical: '🔴',
    danger: '🟠',
    warning: '🟡',
    info: '🔵',
    safe: '🟢'
};

export const CATEGORY_ICONS: Record<string, string> = {
    'Structure': '🏗️',
    'Domain': '🌐',
    'Impersonation': '🎭',
    'Typosquatting': '⌨️',
    'Homograph': '🔤',
    'Obfuscation': '🙈',
    'Security': '🔒',
    'Trust': '✅',
    'Path': '📂',
    'Redirect': '↪️',
    'Length': '📏',
    'Randomness': '🎲',
    'File': '📄',
    'Shortener': '🔗',
    'Encoding': '🔢',
    'WHOIS': '📋',
    'DNS': '🌍',
    'DataURI': '⚠️'
};