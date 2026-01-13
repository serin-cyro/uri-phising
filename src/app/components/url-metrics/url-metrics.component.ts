// =====================================================
// src/app/components/url-metrics/url-metrics.component.ts
// =====================================================

import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { URLFeatures } from '../../models/phishing.models';

interface MetricCard {
  label: string;
  value: string | number;
  icon: string;
  description: string;
  status?: 'good' | 'warning' | 'danger' | 'neutral';
}

interface FlagItem {
  label: string;
  value: boolean;
  goodWhen: boolean;
  icon: string;
}

@Component({
  selector: 'app-url-metrics',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './url-metrics.component.html',
  styleUrls: ['./url-metrics.component.css']
})
export class UrlMetricsComponent {
  @Input() features: URLFeatures | null = null;

  get metricCards(): MetricCard[] {
    if (!this.features) return [];

    return [
      {
        label: 'URL Length',
        value: this.features.url_length,
        icon: '📏',
        description: 'Total characters in URL',
        status: this.features.url_length > 100 ? 'warning' : 'neutral'
      },
      {
        label: 'Subdomains',
        value: this.features.num_subdomains,
        icon: '🌐',
        description: 'Number of subdomain levels',
        status: this.features.num_subdomains > 2 ? 'danger' : 'neutral'
      },
      {
        label: 'Domain Entropy',
        value: this.features.domain_entropy?.toFixed(2) || '0.00',
        icon: '🎲',
        description: 'Randomness measure (higher = more random)',
        status: this.features.domain_entropy > 4 ? 'warning' : 'neutral'
      },
      {
        label: 'Path Entropy',
        value: this.features.path_entropy?.toFixed(2) || '0.00',
        icon: '📂',
        description: 'Path randomness measure',
        status: this.features.path_entropy > 4.5 ? 'warning' : 'neutral'
      },
      {
        label: 'Special Chars',
        value: `${((this.features.special_char_ratio || 0) * 100).toFixed(1)}%`,
        icon: '🔣',
        description: 'Percentage of special characters',
        status: (this.features.special_char_ratio || 0) > 0.2 ? 'warning' : 'neutral'
      },
      {
        label: 'Digits in URL',
        value: this.features.num_digits,
        icon: '🔢',
        description: 'Number count in URL',
        status: this.features.num_digits > 10 ? 'warning' : 'neutral'
      },
      {
        label: 'Parameters',
        value: this.features.num_params,
        icon: '❓',
        description: 'Query parameters count',
        status: this.features.num_params > 5 ? 'warning' : 'neutral'
      },
      {
        label: 'Path Length',
        value: this.features.path_length,
        icon: '📍',
        description: 'Characters in path',
        status: this.features.path_length > 50 ? 'warning' : 'neutral'
      }
    ];
  }

  get flagItems(): FlagItem[] {
    if (!this.features) return [];

    return [
      {
        label: 'HTTPS',
        value: this.features.has_https,
        goodWhen: true,
        icon: '🔒'
      },
      {
        label: 'IP Address',
        value: this.features.has_ip,
        goodWhen: false,
        icon: '🖥️'
      },
      {
        label: 'Has Port',
        value: this.features.has_port,
        goodWhen: false,
        icon: '🚪'
      },
      {
        label: 'Punycode',
        value: this.features.has_punycode,
        goodWhen: false,
        icon: '🔤'
      },
      {
        label: '@ Symbol',
        value: this.features.has_at_symbol,
        goodWhen: false,
        icon: '@'
      },
      {
        label: 'Double Slash',
        value: this.features.has_double_slash,
        goodWhen: false,
        icon: '//'
      },
      {
        label: 'Shortened URL',
        value: this.features.is_shortened,
        goodWhen: false,
        icon: '🔗'
      }
    ];
  }

  getFlagStatus(flag: FlagItem): 'good' | 'bad' | 'neutral' {
    if (!flag.value) {
      return flag.goodWhen ? 'bad' : 'good';
    }
    return flag.goodWhen ? 'good' : 'bad';
  }

  getFlagIcon(flag: FlagItem): string {
    const status = this.getFlagStatus(flag);
    if (flag.label === 'HTTPS') {
      return flag.value ? '✓' : '✗';
    }
    return status === 'good' ? '✓' : '!';
  }
}