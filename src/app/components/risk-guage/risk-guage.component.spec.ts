import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RiskGuageComponent } from './risk-guage.component';

describe('RiskGuageComponent', () => {
  let component: RiskGuageComponent;
  let fixture: ComponentFixture<RiskGuageComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RiskGuageComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RiskGuageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
