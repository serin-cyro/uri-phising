import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Finding, LEVEL_ICONS, CATEGORY_ICONS } from '../../models/phishing.models';

interface CategoryTab {
  name: string;
  icon: string;
  count: number;
}

@Component({
  selector: 'app-findings-list',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './findings-list.component.html',
  styleUrls: ['./findings-list.component.css']
})
export class FindingsListComponent implements OnChanges {
  @Input() findings: Finding[] = [];

  selectedCategory = 'All';
  categories: CategoryTab[] = [];
  expandedFindings: Set<number> = new Set();

  // Sorting
  sortBy: 'severity' | 'category' | 'impact' = 'severity';
  sortDirection: 'asc' | 'desc' = 'desc';

  private readonly severityOrder: Record<string, number> = {
    critical: 5,
    danger: 4,
    warning: 3,
    info: 2,
    safe: 1
  };

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['findings']) {
      this.buildCategories();
      this.selectedCategory = 'All';
      this.expandedFindings.clear();
    }
  }

  private buildCategories(): void {
    const grouped = new Map<string, number>();
    
    this.findings.forEach(f => {
      grouped.set(f.category, (grouped.get(f.category) || 0) + 1);
    });

    this.categories = [
      { name: 'All', icon: '📁', count: this.findings.length }
    ];

    // Sort categories by count
    const sortedCategories = Array.from(grouped.entries())
      .sort((a, b) => b[1] - a[1]);

    sortedCategories.forEach(([name, count]) => {
      this.categories.push({
        name,
        icon: this.getCategoryIcon(name),
        count
      });
    });
  }

  get filteredFindings(): Finding[] {
    let result = this.selectedCategory === 'All'
      ? [...this.findings]
      : this.findings.filter(f => f.category === this.selectedCategory);

    // Sort findings
    result.sort((a, b) => {
      let comparison = 0;
      
      switch (this.sortBy) {
        case 'severity':
          comparison = this.severityOrder[b.level] - this.severityOrder[a.level];
          break;
        case 'category':
          comparison = a.category.localeCompare(b.category);
          break;
        case 'impact':
          comparison = Math.abs(b.score_impact) - Math.abs(a.score_impact);
          break;
      }

      return this.sortDirection === 'desc' ? comparison : -comparison;
    });

    return result;
  }

  get dangerCount(): number {
    return this.findings.filter(f => f.level === 'critical' || f.level === 'danger').length;
  }

  get warningCount(): number {
    return this.findings.filter(f => f.level === 'warning').length;
  }

  get safeCount(): number {
    return this.findings.filter(f => f.level === 'safe').length;
  }

  selectCategory(category: string): void {
    this.selectedCategory = category;
  }

  toggleSort(field: 'severity' | 'category' | 'impact'): void {
    if (this.sortBy === field) {
      this.sortDirection = this.sortDirection === 'desc' ? 'asc' : 'desc';
    } else {
      this.sortBy = field;
      this.sortDirection = 'desc';
    }
  }

  toggleExpand(index: number): void {
    if (this.expandedFindings.has(index)) {
      this.expandedFindings.delete(index);
    } else {
      this.expandedFindings.add(index);
    }
  }

  isExpanded(index: number): boolean {
    return this.expandedFindings.has(index);
  }

  getLevelIcon(level: string): string {
    return LEVEL_ICONS[level] || '⚪';
  }

  getCategoryIcon(category: string): string {
    return CATEGORY_ICONS[category] || '📌';
  }

  getScoreClass(impact: number): string {
    if (impact < 0) return 'positive';
    if (impact >= 30) return 'critical';
    if (impact >= 20) return 'danger';
    if (impact >= 10) return 'warning';
    return 'info';
  }

  trackByIndex(index: number): number {
    return index;
  }
}
