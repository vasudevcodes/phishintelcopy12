# PhishIntel — Phase 1: Foundation & Email Forensic Parser

PhishIntel is a modern, high-performance forensic email investigation platform designed to analyze raw RFC 5322 email files (`.eml`) in an isolated, secure local environment. 

Phase 1 establishes the core forensic ingestion engine, deep header parser, transit hop reconstructor, URL extractor, attachment hasher, and cyber investigation dashboard—without premature machine learning or external cloud dependencies.

---

## Key Capabilities (Phase 1)

- **Transit Hop Extraction**: Preserves the complete chain of all `Received` headers exactly as extracted from the email (where Hop #0 is typically the newest/most recent hop, and the final hop is typically the oldest hop closest to origin).
- **Candidate IP Extraction & Classification**: Detects IPv4 and IPv6 addresses across transit hops and strictly classifies them into distinct scopes: RFC 1918 `Private`, `Documentation` (TEST-NET-1/2/3, 2001:db8::/32), `Loopback`, `Link-Local`, `Multicast`, `Special-Purpose`, `Reserved`, or `Public`. Avoids blanket labeling based on `is_private`.
  > *Forensic Principle*: PhishIntel preserves evidence and never assumes the first IP found is the originating sender.
- **Sanitized Body Inspection**: Extracts `text/plain` content and safely sanitizes `text/html` bodies (stripping `<script>`, `<style>`, and active markup). Untrusted HTML is never executed or rendered directly in the browser.
- **Passive URL Extraction & Deduplication**: Harvests URLs across plain-text content and HTML `<a>` tags while recording source origin. URLs are strictly non-clickable and never visited, resolved, or pre-fetched.
- **Isolated Attachment Forensics**: Calculates cryptographic SHA-256 digests and extracts MIME metadata in memory without executing or writing executable files.
- **Single-File Upload Engine**: Enforces strict validation (`.eml` only, 10 MB maximum, rejection of empty files, zero retention of analysis history).

---

## Project Structure

```
PhishIntel/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI application entry point with CORS
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── router.py           # API v1 route aggregator
│   │   │       └── endpoints/
│   │   │           └── email.py        # POST /api/v1/email/analyze endpoint
│   │   ├── core/
│   │   │   └── config.py               # Application settings and limits
│   │   ├── schemas/
│   │   │   └── email.py                # Pydantic forensic models
│   │   └── services/
│   │       ├── email_parser.py         # RFC 5322 parser, body & URL extractor
│   │       └── ip_extractor.py         # Transit hop IP extractor & classifier
│   ├── tests/
│   │   ├── fixtures/                   # 8 synthetic .eml forensic test fixtures
│   │   ├── test_email_parser.py        # Unit tests for parser and IP classification
│   │   └── test_api.py                 # Integration tests for upload & schema
│   ├── pytest.ini                      # Pytest configuration
│   └── requirements.txt                # Python backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx              # Cybersecurity header bar
│   │   │   ├── UploadZone.tsx          # Drag & drop upload area with validation
│   │   │   ├── EmailOverviewBanner.tsx # Metadata, hop counters & parser notices
│   │   │   ├── HeaderForensics.tsx     # RFC headers, Auth-Results, Received hops
│   │   │   ├── IPCandidatesCard.tsx    # IP candidates with classification badges
│   │   │   ├── ExtractedURLsCard.tsx   # Deduplicated URLs and domain breakdown
│   │   │   ├── AttachmentForensicsCard.tsx # Attachments and SHA-256 hashes
│   │   │   └── BodyForensicsCard.tsx   # Sanitized plain text & HTML text viewer
│   │   ├── types/
│   │   │   └── forensics.ts            # TypeScript interfaces
│   │   ├── App.tsx                     # Main dashboard layout and tab navigation
│   │   ├── index.css                   # Tailwind base and cyber styling
│   │   └── main.tsx                    # React DOM entry point
│   ├── tailwind.config.js              # Custom cyber dark theme colors
│   ├── postcss.config.js
│   ├── vite.config.ts                  # Vite config with backend proxy
│   └── package.json
├── docs/
│   ├── architecture.md                 # Phase 1 architectural design
│   ├── implementation_log.md           # Step-by-step engineering log
│   └── phase1_validation.md            # Test results, limits, and verification
├── README.md
└── .gitignore
```

---

## Installation & Startup (Windows)

### Prerequisites
- Python 3.11+ (verified on Python 3.13)
- Node.js 18+ and npm
- Windows PowerShell

### 1. Backend Setup

Open a PowerShell terminal in `PhishIntel/backend`:

```powershell
cd c:\Users\Lenovo\Desktop\PhishIntel\backend

# 1. Create Python virtual environment
python -m venv .venv

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated test suite
pytest -v

# 5. Start FastAPI backend server (runs on port 8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Backend interactive documentation is available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/health`

---

### 2. Frontend Setup

Open a separate PowerShell terminal in `PhishIntel/frontend`:

```powershell
cd c:\Users\Lenovo\Desktop\PhishIntel\frontend

# 1. Install Node.js packages
npm install

# 2. Verify build / TypeScript compilation
npm run build

# 3. Start Vite development server (runs on port 5173)
npm run dev
```

Open your browser and navigate to:
**`http://127.0.0.1:5173`**

---

## API Specification

### `POST /api/v1/email/analyze`
Accepts a single `.eml` multipart file upload.

- **Constraints**:
  - Allowed extensions: `.eml`
  - Max upload size: `10 MB` (`10,485,760 bytes`)
  - Content: Non-empty RFC 5322 message
- **Responses**:
  - `200 OK`: Returns complete forensic JSON (`EmailAnalysisResponse`).
  - `400 Bad Request`: Invalid extension, empty file, or unparseable format.
  - `413 Content Too Large`: Upload exceeds 10 MB limit.

---

## Security Invariants

1. **Zero External Requests**: Email parsing and IP classification run 100% locally using standard libraries. No external network queries or DNS lookups are performed.
2. **Execution Isolation**: Attachments and files are never saved to executable paths or executed. SHA-256 hashes are computed directly in memory.
3. **No Direct HTML Rendering**: Email HTML is parsed strictly to extract readable text. Active elements (`<script>`, `<style>`, `<iframe>`, `<object>`) are stripped.
4. **URL Neutrality**: Extracted URLs are rendered inert (non-clickable strings) to eliminate accidental clicks.
5. **Zero History Retention**: In-memory parsing only; no email messages or headers are written to a database or retained across sessions.
