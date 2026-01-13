// =====================================================
// src/app/app.component.ts
// =====================================================

import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PhishingDetectorService } from "./services/phishing-detector.service";
import { AnalysisResult, RISK_ICONS } from './models/phishing.models';
import { UrlInputComponent } from './components/url-input/url-input.component';
import { AnalysisResultComponent } from './components/analysis-results/analysis-results.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    UrlInputComponent,
    AnalysisResultComponent
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  private readonly detectorService = inject(PhishingDetectorService);

  result: AnalysisResult | null = null;
  history: AnalysisResult[] = [];
  isLoading = false;
  serverStatus: 'online' | 'offline' | 'checking' = 'checking';

  ngOnInit(): void {
    this.checkServerStatus();
  }

  checkServerStatus(): void {
    this.serverStatus = 'checking';
    this.detectorService.healthCheck().subscribe(response => {
      this.serverStatus = response.status === 'healthy' ? 'online' : 'offline';
    });
  }

  onAnalyze(event: { url: string; deepScan: boolean }): void {
    this.isLoading = true;
    this.result = null;

    this.detectorService.analyzeUrl(event.url, event.deepScan).subscribe({
      next: (result) => {
        this.result = result;
        this.isLoading = false;

        // Add to history if no error
        if (!result.error) {
          this.addToHistory(result);
        }
      },
      error: () => {
        this.isLoading = false;
      }
    });
  }

  onDismissResult(): void {
    this.result = null;
  }

  onReanalyze(url: string): void {
    this.onAnalyze({ url, deepScan: false });
  }

  selectFromHistory(item: AnalysisResult): void {
    this.result = item;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  clearHistory(): void {
    this.history = [];
  }

  removeFromHistory(index: number, event: Event): void {
    event.stopPropagation();
    this.history.splice(index, 1);
  }

  getRiskIcon(level: string): string {
    return RISK_ICONS[level as keyof typeof RISK_ICONS] || '⚪';
  }

  private addToHistory(result: AnalysisResult): void {
    // Avoid duplicates
    const exists = this.history.some(h => h.url === result.url);
    if (!exists) {
      this.history = [result, ...this.history.slice(0, 9)];
    }
  }

  trackByUrl(index: number, item: AnalysisResult): string {
    return item.url;
  }
}