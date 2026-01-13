// =====================================================
// src/app/components/url-input/url-input.component.ts
// =====================================================

import { Component, Output, EventEmitter, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormControl, Validators, ReactiveFormsModule, FormsModule } from '@angular/forms';

interface TestUrl {
  label: string;
  value: string;
  description: string;
}

@Component({
  selector: 'app-url-input',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, FormsModule],
  templateUrl: './url-input.component.html',
  styleUrls: ['./url-input.component.css']
})
export class UrlInputComponent {
  @Input() isLoading = false;
  @Output() analyze = new EventEmitter<{ url: string; deepScan: boolean }>();

  urlControl = new FormControl('', [
    Validators.required,
    Validators.minLength(4)
  ]);

  deepScan = false;
  showTestUrls = false;

  testUrls: TestUrl[] = [
    {
      label: '✅ Safe - Google',
      value: 'https://www.google.com',
      description: 'Legitimate trusted domain'
    },
    {
      label: '✅ Safe - GitHub',
      value: 'https://github.com/user/repo',
      description: 'Legitimate trusted domain'
    },
    {
      label: '⚠️ Typosquatting',
      value: 'http://g00gle-login.tk/verify',
      description: 'Number substitution + suspicious TLD'
    },
    {
      label: '🔴 Brand Impersonation',
      value: 'http://paypa1-secure.xyz/signin',
      description: 'Fake PayPal with suspicious domain'
    },
    {
      label: '🔴 IP-based URL',
      value: 'http://192.168.1.1/admin/login.php',
      description: 'Uses IP instead of domain'
    },
    {
      label: '⚠️ URL Shortener',
      value: 'http://bit.ly/3abc123',
      description: 'Hidden destination URL'
    },
    {
      label: '🔴 Homograph Attack',
      value: 'http://аpple.com/id',
      description: 'Cyrillic "а" instead of Latin "a"'
    },
    {
      label: '🔴 Excessive Subdomains',
      value: 'https://secure.login.account.microsoft.verify.xyz/auth',
      description: 'Many subdomains to confuse users'
    },
    {
      label: '⚠️ Open Redirect',
      value: 'https://example.com/redirect?url=http://evil.com',
      description: 'Contains redirect parameter'
    },
    {
      label: '🔴 Data URI',
      value: 'data:text/html,<script>alert(1)</script>',
      description: 'Embedded malicious content'
    }
  ];

  setUrl(url: string): void {
    this.urlControl.setValue(url);
    this.onAnalyze();
  }

  onAnalyze(): void {
    if (this.urlControl.valid && this.urlControl.value) {
      this.analyze.emit({
        url: this.urlControl.value.trim(),
        deepScan: this.deepScan
      });
    }
  }

  clearInput(): void {
    this.urlControl.reset();
  }

  toggleTestUrls(): void {
    this.showTestUrls = !this.showTestUrls;
  }
}