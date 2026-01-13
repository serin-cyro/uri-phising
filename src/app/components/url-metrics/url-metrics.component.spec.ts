import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UrlMetricsComponent } from './url-metrics.component';

describe('UrlMetricsComponent', () => {
  let component: UrlMetricsComponent;
  let fixture: ComponentFixture<UrlMetricsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UrlMetricsComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(UrlMetricsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
