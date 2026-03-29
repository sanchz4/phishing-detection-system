# Phishing Detection System

Modernized phishing-analysis workspace with a typed Python backend and a React dashboard for bank-focused URL triage.

## Tech Stack

- Backend: Python 3.11, FastAPI, Selenium, optional TensorFlow, scikit-learn
- Frontend: Vite, React, TypeScript, Tailwind CSS, React Router, React Query
- Tooling: ESLint, Prettier, concurrently

## Project Structure

```text
src/                     Python backend, API, CLI, and analysis modules
frontend/                Vite + React dashboard
bank_screenshots/        Reference screenshots used for similarity matching
data/                    Generated crawl and monitoring artifacts
requirements.txt         Backend dependencies
package.json             Root scripts for full-stack development
config.json              Non-secret runtime configuration
```

## Setup

1. Create and activate a Python virtual environment.
2. Install backend dependencies with `python -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and add any API keys you want enabled.
4. Install frontend and root tooling with `npm install` and `npm --prefix frontend install`.

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
- `POST /api/analyze`

Example request:

```json
{
  "urls": ["https://example.com"],
  "comprehensive": true
}
```

## Folder Structure

- `src/api.py`: FastAPI application and REST endpoints
- `src/service.py`: orchestration layer between API/CLI and detector logic
- `src/cli.py`: streamlined command-line entrypoint
- `frontend/src/components`: reusable UI components
- `frontend/src/pages`: route-level views and fallbacks
- `frontend/src/hooks`: React Query and dashboard hooks
- `frontend/src/services`: typed API client layer
- `frontend/src/store`: shared app-level client/store setup

## Notes

- `config.json` no longer stores live secrets. Use environment variables instead.
- If TensorFlow is unavailable, the backend falls back to histogram-based image features so the API can still start.
