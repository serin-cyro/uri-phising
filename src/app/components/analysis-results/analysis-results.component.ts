// =====================================================
// src/app/components/analysis-result/analysis-result.component.ts
// =====================================================

import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { trigger, transition, style, animate } from '@angular/animations';
import { AnalysisResult, RiskLevel } from '../../models/phishing.models';
import { RiskGuageComponent } from '../risk-guage/risk-guage.component';
import { FindingsListComponent } from '../findings-list/findings-list.component';
import { UrlMetricsComponent } from '../url-metrics/url-metrics.component';

@Component({
  selector: 'app-analysis-result',
  standalone: true,
  imports: [
    CommonModule,
    DecimalPipe,
    RiskGuageComponent,
    FindingsListComponent,
    UrlMetricsComponent
  ],
  templateUrl: './analysis-results.component.html',
  styleUrls: ['./analysis-results.component.css'],
  animations: [
    trigger('fadeSlideIn', [
      transition(':enter', [
        style({ opacity: 0, transform: 'translateY(20px)' }),
        animate('400ms ease-out', style({ opacity: 1, transform: 'translateY(0)' }))
      ])
    ]),
    trigger('fadeIn', [
      transition(':enter', [
        style({ opacity: 0 }),
        animate('300ms ease-out', style({ opacity: 1 }))
      ])
    ])
  ]
})
export class AnalysisResultComponent {
  @Input() result: AnalysisResult | null = null;
  @Output() dismiss = new EventEmitter<void>();
  @Output() reanalyze = new EventEmitter<string>();

  activeTab: 'findings' | 'metrics' = 'findings';

  get hasError(): boolean {
    return !!this.result?.error;
  }

  get riskLevelClass(): string {
    return (this.result?.risk_level || 'LOW').toLowerCase();
  }

  get dangerFindingsCount(): number {
    if (!this.result) return 0;
    return this.result.findings.filter(f => 
      f.level === 'critical' || f.level === 'danger'
    ).length;
  }

  get warningFindingsCount(): number {
    if (!this.result) return 0;
    return this.result.findings.filter(f => f.level === 'warning').length;
  }

  get safeFindingsCount(): number {
    if (!this.result) return 0;
    return this.result.findings.filter(f => f.level === 'safe').length;
  }

  setActiveTab(tab: 'findings' | 'metrics'): void {
    this.activeTab = tab;
  }

  onDismiss(): void {
    this.dismiss.emit();
  }

  onReanalyze(): void {
    if (this.result?.url) {
      this.reanalyze.emit(this.result.url);
    }
  }

  copyUrl(): void {
    if (this.result?.url) {
      navigator.clipboard.writeText(this.result.url);
    }
  }

  formatUrl(url: string): string {
    if (url.length > 80) {
      return url.substring(0, 77) + '...';
    }
    return url;
  }
}