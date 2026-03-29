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

## Notes

- `config.json` no longer stores live secrets. Use environment variables instead.
- If TensorFlow is unavailable, the backend falls back to histogram-based image features so the API can still start.
- The current workspace does not contain Git metadata, so commit and push operations require a real Git checkout or repo initialization with the correct remote.
