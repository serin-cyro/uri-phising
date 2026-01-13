// =====================================================
// src/app/components/risk-gauge/risk-gauge.component.ts
// =====================================================

import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule, DecimalPipe, NgIf } from '@angular/common';
import { RiskLevel, RISK_COLORS, RISK_ICONS } from '../../models/phishing.models';

interface RiskConfig {
  colorStart: string;
  colorEnd: string;
  icon: string;
  message: string;
  bgClass: string;
}

@Component({
  selector: 'app-risk-guage',
  standalone: true,
  imports: [CommonModule, DecimalPipe,],
  templateUrl: './risk-guage.component.html',
  styleUrls: ['./risk-guage.component.css']
})
export class RiskGuageComponent implements OnChanges {
  @Input() score: number = 0;
  @Input() riskLevel: RiskLevel = 'LOW';
  @Input() analysisTime: number = 0;

  // SVG gauge calculations
  readonly arcLength = 251.2;
  dashOffset = 251.2; // Start with full offset (empty arc)
  
  // Display properties
  colorStart = '#22c55e';
  colorEnd = '#16a34a';
  scoreColor = '#22c55e';
  levelIcon = '🟢';
  riskMessage = '';
  bgClass = 'low';

  // Animation
  displayScore = 0;
  private animationFrame: number | null = null;

  private readonly riskConfigs: Record<string, RiskConfig> = {
    CRITICAL: {
      colorStart: '#ef4444',
      colorEnd: '#dc2626',
      icon: '🔴',
      message: 'CRITICAL RISK - Highly likely to be phishing. Do not visit!',
      bgClass: 'critical'
    },
    HIGH: {
      colorStart: '#f97316',
      colorEnd: '#ea580c',
      icon: '🟠',
      message: 'HIGH RISK - Strong phishing indicators detected. Exercise extreme caution.',
      bgClass: 'high'
    },
    MEDIUM: {
      colorStart: '#eab308',
      colorEnd: '#ca8a04',
      icon: '🟡',
      message: 'MEDIUM RISK - Some suspicious elements found. Verify before proceeding.',
      bgClass: 'medium'
    },
    LOW: {
      colorStart: '#22c55e',
      colorEnd: '#16a34a',
      icon: '🟢',
      message: 'LOW RISK - URL appears relatively safe.',
      bgClass: 'low'
    }
  };

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['score'] || changes['riskLevel']) {
      this.updateGauge();
      this.animateScore();
    }
  }

  private updateGauge(): void {
    const config = this.riskConfigs[this.riskLevel] || this.riskConfigs['LOW'];
    
    this.colorStart = config.colorStart;
    this.colorEnd = config.colorEnd;
    this.scoreColor = config.colorStart;
    this.levelIcon = config.icon;
    this.riskMessage = config.message;
    this.bgClass = config.bgClass;
    
    // Calculate dash offset for arc fill
    // When score is 0, show just the dot at start (small visible amount)
    // When score is 100, offset should be 0 (full)
    const percentage = this.score / 100;
    
    if (this.score === 0) {
      // Show just the rounded cap at the start (left side)
      this.dashOffset = this.arcLength - 1; // Tiny visible portion for the dot
    } else {
      this.dashOffset = this.arcLength * (1 - percentage);
    }
  }

  private animateScore(): void {
    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
    }

    const startScore = this.displayScore;
    const endScore = this.score;
    const duration = 1000;
    const startTime = performance.now();

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (ease-out)
      const easeOut = 1 - Math.pow(1 - progress, 3);
      
      this.displayScore = Math.round(startScore + (endScore - startScore) * easeOut);
      
      if (progress < 1) {
        this.animationFrame = requestAnimationFrame(animate);
      }
    };

    this.animationFrame = requestAnimationFrame(animate);
  }

  getGradientId(): string {
    return 'gaugeGradient';
  }

  getGradientUrl(): string {
    return `url(#${this.getGradientId()})`;
  }
}