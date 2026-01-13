URL Phishing Detector

A modern, real-time URL phishing detection application built with Angular 19 and Python FastAPI. Analyze URLs for potential phishing threats using advanced heuristic analysis and machine learning-ready feature extraction.

Detection Capabilities (Expected Hopefully)
- "IP Address Detection" - Flags URLs using raw IP addresses instead of domains
- "Suspicious TLD Analysis" - Identifies high-risk top-level domains (.tk, .xyz, .click, etc.)
- "Brand Impersonation" - Detects fake versions of trusted brands (Google, PayPal, Microsoft, etc.)
- "Typosquatting Detection" - Catches character substitutions (g00gle, paypa1, micros0ft)
- "Homograph Attack Detection" - Identifies Unicode lookalike characters (Cyrillic а vs Latin a)
- "URL Obfuscation" - Detects @ symbols, excessive encoding, and redirect parameters
- "Entropy Analysis" - Flags randomly generated domains using Shannon entropy
- "URL Shortener Detection" - Identifies hidden destinations behind short links
- "Deep Scan Mode" - Optional WHOIS, DNS, and SSL certificate verification


Quick Start Guide

Prerequisites
- Node.js 18+ and npm
- Python 3.10+ (for backend)
- Angular CLI 19+

Frontend Setup

# Clone the repository
git clone https://github.com/yourusername/url-phishing-detector.git
cd url-phishing-detector

# Install dependencies
npm install

# Start development server
ng serve

# Open browser at http://localhost:4200
```

### Backend Setup (Optional hoping to host it on a server and a work in progress )

# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000


Project Structure

url-phishing-detector/
├── src/
│   ├── app/
│   │   ├── components/
│   │   │   ├── url-input/          # URL input with test URLs
│   │   │   ├── risk-gauge/         # Animated SVG gauge
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

Testing with Mock Data

The UI as of now includes a built-in mock mode for testing without the backend:

// In phishing-detector.service.ts
private readonly useMock = true;  // Set to true for mock data

// you can add / remove testcases

Test URLs

| URL | Expected Risk |
|-----|---------------|
| `https://www.google.com` | ✅ LOW |
| `http://g00gle-login.tk/verify` | 🔴 CRITICAL |
| `http://192.168.1.1/admin` | 🟠 HIGH |
| `http://paypal-secure.xyz/signin` | 🔴 CRITICAL |
| `http://bit.ly/abc123` | 🟡 MEDIUM |

API Endpoints (Takes time to create!!!)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze single URL |
| `POST` | `/api/analyze/batch` | Analyze multiple URLs |
| `GET` | `/api/features/{url}` | Get ML feature vector |
| `GET` | `/api/trusted-domains` | List trusted domains |
| `GET` | `/api/suspicious-tlds` | List suspicious TLDs |
| `GET` | `/health` | Health check |



Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

