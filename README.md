# Phishing Detection System

Modernized phishing-analysis workspace with a typed Python backend and a React dashboard for phishing, quishing, brand-impersonation, and email triage.

## Tech Stack

- Backend: Python 3.11, FastAPI, Selenium, scikit-learn, XGBoost, LightGBM, optional SHAP
- Frontend: Vite, React 18, TypeScript, Tailwind CSS, React Router, React Query, Radix UI, Framer Motion
- Tooling: ESLint, Prettier, concurrently

## Project Structure

```text
src/                     Python backend, API, CLI, analysis, threat feeds, and history store
frontend/                React dashboard with landing, scan, history, and about pages
bank_screenshots/        Reference screenshots used for similarity matching
data/                    Generated crawl and monitoring artifacts
requirements.txt         Backend dependencies
package.json             Root scripts for full-stack development
config.json              Non-secret runtime configuration
```

## Setup

1. Create and activate a Python virtual environment.
2. Install backend dependencies with `python -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and add any API keys you want enabled, including `SAFE_BROWSING_API_KEY` when available.
4. Install frontend and root tooling with `npm install` and `npm --prefix frontend install`.

## Deployment

### Frontend on GitHub Pages

- The repo now includes `.github/workflows/deploy-frontend-pages.yml`, which builds the `frontend/` app on every push to `main` and deploys it to GitHub Pages.
- The frontend uses hash-based routing plus relative asset paths, so it can be served from the repository Pages URL without custom rewrite rules.
- Set the repository variable `VITE_API_BASE_URL` in GitHub before relying on the live site. This should point to your deployed backend base URL, for example `https://your-backend-host.example.com`.

### Backend on Render

- The repo now includes `render.yaml` for a FastAPI web service deployment on Render.
- After creating a new Render Blueprint from this repository, set `APP_CORS_ORIGINS` to include your local frontend URL and your GitHub Pages URL.
- Optional threat-intelligence integrations remain env-driven: `SAFE_BROWSING_API_KEY`, `ICANN_API_KEY`, `VT_API_KEY`, `SECURITYTRAILS_API_KEY`, and `URLSCAN_API_KEY`.
- The SQLite history store will work on a single instance, but keep in mind that many hosted platforms use ephemeral disks unless persistent storage is added.

## Available Scripts

- `npm run dev`: run backend and frontend together
- `npm run dev:backend`: start the FastAPI backend on port `8000`
- `npm run dev:frontend`: start the Vite frontend on port `5173`
- `npm run backend:cli -- --url https://example.com`: run the modern Python CLI directly
- `npm run build`: build the frontend
- `npm run lint`: run frontend ESLint

## API

- `GET /api/health`
- `GET /api/config`
- `GET /api/stats`
- `GET /api/history`
- `POST /api/analyze`
- `DELETE /api/history`

Example request:

```json
{
  "inputs": ["https://example.com"],
  "input_type": "url",
  "comprehensive": true
}
```

## Folder Structure

- `src/api.py`: FastAPI application and REST endpoints
- `src/service.py`: orchestration layer between API/CLI and detector logic
- `src/cyber_engine.py`: cybersecurity analysis engine with heuristic, ML, HTML, TLS, and threat-feed checks
- `src/history_store.py`: SQLite-backed scan history
- `src/cli.py`: streamlined command-line entrypoint
- `.github/workflows/deploy-frontend-pages.yml`: GitHub Pages build and deploy workflow
- `render.yaml`: Render blueprint for the hosted FastAPI backend
- `frontend/src/components`: reusable UI components
- `frontend/src/pages`: route-level views and fallbacks
- `frontend/src/hooks`: React Query and dashboard hooks
- `frontend/src/services`: typed API client layer
- `frontend/src/store`: shared app-level client/store setup

## Notes

- `config.json` no longer stores live secrets. Use environment variables instead.
- The backend now returns risk score, threat category, confidence level, explanation, and persisted scan history for every scan.
- If TensorFlow is unavailable, the backend falls back to histogram-based image features so the API can still start.
