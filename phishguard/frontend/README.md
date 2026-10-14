# PhishGuard — Frontend Client

The official web user interface for **PhishGuard: Phishing Website Detection Using Random Forest**.

PhishGuard provides a modern, dark cybersecurity dashboard that communicates seamlessly with the FastAPI backend service (`POST /api/analyze` and `GET /api/health`). Users can paste any website URL to receive instant ML-driven threat analysis, confidence probabilities, and a calibrated 0–100 risk score with zero webpage crawling.

---

## 1. Tech Stack & Architecture

- **Core Framework**: React 19 (TypeScript)
- **Bundler & Tooling**: Vite
- **Styling**: Tailwind CSS with custom glassmorphism and cybersecurity design tokens
- **Typography**: Inter (UI / Headings) & JetBrains Mono (Technical telemetry / URLs / Metrics)
- **Icons**: Lucide React

### Directory Structure
```
frontend/
├── src/
│   ├── components/
│   │   ├── Navbar.tsx        # Top navigation, brand, and live model status badge
│   │   ├── Hero.tsx          # Headline, subtitle, and scanner container
│   │   ├── UrlScanner.tsx    # URL input, step-wise loading animation, and presets
│   │   ├── ResultCard.tsx    # Threat outcome banner, probabilities, and technical telemetry
│   │   ├── RiskScore.tsx     # 0–100 circular SVG gauge with calibrated risk thresholds
│   │   ├── HowItWorks.tsx    # 3-step zero-crawl architectural explanation
│   │   ├── ModelSection.tsx  # Random Forest classifier specifications and benchmarks
│   │   ├── FeatureGrid.tsx   # Visual breakdown of the 21 production feature categories
│   │   └── Footer.tsx        # Academic project context and security disclaimer
│   ├── services/
│   │   └── api.ts            # Centralized API service for FastAPI communication
│   ├── types/
│   │   └── api.ts            # TypeScript interfaces for requests, responses, and errors
│   ├── App.tsx               # Root application state orchestrator
│   ├── main.tsx              # DOM mount entrypoint
│   └── index.css             # Tailwind directives and custom glass panel utilities
├── public/                   # Static assets
├── .env                      # Environment configuration (VITE_API_BASE_URL)
├── .env.example              # Template environment configuration
├── tailwind.config.js        # Cybersecurity design tokens and theme extensions
├── postcss.config.js         # PostCSS configuration
├── package.json              # Node dependencies and scripts
└── README.md                 # Frontend documentation
```

---

## 2. Design System & Cybersecurity Aesthetic

The UI adheres strictly to a professional, dark cybersecurity aesthetic:
- **Background**: `#08090A` (Near-black)
- **Surfaces & Cards**: `#0E1012` and `#13161A` (Layered glassmorphism panels)
- **Primary Accent**: `#6EA8FF` (Subtle cyber blue)
- **Safe / Legitimate**: `#22C55E` (Restrained emerald green)
- **Threat / Phishing**: `#EF4444` (Restrained red)
- **Warning / Moderate**: `#F59E0B` (Restrained amber)
- **Borders**: `#232830` (Subtle dark slate)

---

## 3. Getting Started

### Prerequisites
- Node.js v18+ (tested with Node v24)
- npm v9+

### Installation
```bash
# Navigate to the frontend directory
cd phishguard/frontend

# Install dependencies
npm install
```

### Running the Development Server
```bash
npm run dev
```
The application will be available at `http://127.0.0.1:5173/`.

### Building for Production
```bash
npm run build
```
Creates an optimized production bundle in `dist/`.

---

## 4. API Configuration

The frontend communicates with the FastAPI backend using the `VITE_API_BASE_URL` environment variable defined in `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

### Key API Endpoints Used:
1. `GET /api/health`: Checked once on initial load to confirm that the Random Forest model is loaded and ready.
2. `POST /api/analyze`: Submits the URL payload `{"url": "https://example.com"}` and receives:
   ```json
   {
     "url": "https://example.com",
     "prediction": "legitimate",
     "label": 1,
     "probability": 0.95,
     "risk_score": 5
   }
   ```

---

## 5. Security & Operational Rules

1. **Zero-Crawl Safety**: The frontend never connects directly to or scrapes the target URL. All validation and feature extraction take place in the isolated backend service.
2. **Deterministic Inputs**: The URL input accepts only `http://` and `https://` schemas with valid domain or IP formatting.
3. **No External APIs**: The frontend relies solely on the local FastAPI Random Forest inference pipeline (no third-party tracking or cloud dependencies).
4. **Accessible Feedback**: Loading states, progress steps, and error notifications utilize `aria-live` and semantic status roles.
