# 🛡️ URL Phishing Detector

A modern, real-time URL phishing detection application built with **Angular 19** and **Python FastAPI**. Analyze URLs for potential phishing threats using advanced heuristic analysis and machine learning-ready feature extraction.


##  Features(Hopefully)

###  Detection Capabilities (A work in progress)
- **IP Address Detection** - Flags URLs using raw IP addresses instead of domains
- **Suspicious TLD Analysis** - Identifies high-risk top-level domains (.tk, .xyz, .click, etc.)
- **Brand Impersonation** - Detects fake versions of trusted brands (Google, PayPal, Microsoft, etc.)
- **Typosquatting Detection** - Catches character substitutions (g00gle, paypa1, micros0ft)
- **Homograph Attack Detection** - Identifies Unicode lookalike characters (Cyrillic а vs Latin a)
- **URL Obfuscation** - Detects @ symbols, excessive encoding, and redirect parameters
- **Entropy Analysis** - Flags randomly generated domains using Shannon entropy
- **URL Shortener Detection** - Identifies hidden destinations behind short links
- **Deep Scan Mode** - Optional WHOIS, DNS, and SSL certificate verification


##  Quick Start

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+ (for backend)
- Angular CLI 19+

### Frontend Setup

```bash
# Clone the repository
git clone https://github.com/serin-cyro/uri-phising.git
cd uri-phising

# Install dependencies
npm install

# Start development server
ng serve

# Open browser at http://localhost:4200
```

## Project Structure

```
uri-phising/
├── src/
│   ├── app/
│   │   ├── components/
│   │   │   ├── url-input/          # URL input with test URLs
│   │   │   ├── risk-guage/         # Animated SVG gauge
│   │   │   ├── findings-list/      # Categorized findings
│   │   │   ├── url-metrics/        # Technical metrics
│   │   │   └── analysis-result/    # Main result container
│   │   ├── models/
│   │   │   └── phishing.models.ts  # TypeScript interfaces
│   │   ├── services/
│   │   │   └── phishing-detector.service.ts
│   │   ├── app.component.ts
│   │   └── app.config.ts
│   ├── styles.scss                 # Global styles
│   └── index.html
├── backend/
│   ├── main.py                     # FastAPI server
│   ├── phishing_detector.py        # Detection engine
│   └── requirements.txt
└── README.md
```

## Testing with Mock Data

The application includes a built-in mock mode for testing without the backend:

```typescript
// In phishing-detector.service.ts
private readonly useMock = true;  // Set to true for mock data
```

### Test URLs

| URL | Expected Risk |
|-----|---------------|
| `https://www.google.com` | ✅ LOW |
| `http://g00gle-login.tk/verify` | 🔴 CRITICAL |
| `http://192.168.1.1/admin` | 🟠 HIGH |
| `http://paypal-secure.xyz/signin` | 🔴 CRITICAL |
| `http://bit.ly/abc123` | 🟡 MEDIUM |

## 🔌 API Endpoints (A work in progress)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze single URL |
| `POST` | `/api/analyze/batch` | Analyze multiple URLs |
| `GET` | `/api/features/{url}` | Get ML feature vector |
| `GET` | `/api/trusted-domains` | List trusted domains |
| `GET` | `/api/suspicious-tlds` | List suspicious TLDs |
| `GET` | `/health` | Health check |
