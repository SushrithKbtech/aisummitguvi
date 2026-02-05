# Agentic Honeypot API (FastAPI)

## Quick Start

1. Install deps

```bash
pip install -r requirements.txt
```

2. Set env vars

```bash
set API_KEY=your_api_key
set OPENAI_API_KEY=your_openai_key
set OPENAI_MODEL=gpt-4o-mini
set GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

3. Run

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Railway

- Set `PORT` and the env vars in `.env.example` on Railway.
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`

## Endpoint

`POST /message`

Headers:
- `x-api-key: <API_KEY>`
- `Content-Type: application/json`

Body matches the hackathon format.

## Notes
- Callback is sent automatically when scam is detected and completion heuristics are met.
- Set `MAX_SCAMMER_MESSAGES` or `MAX_TOTAL_MESSAGES` (>0) if you want a hard cap. `0` disables caps.
- You can tune behavior with env vars in `app.py`.
