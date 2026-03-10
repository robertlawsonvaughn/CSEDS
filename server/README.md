# CSEDS Server

FastAPI + SQLite3 reference implementation.

## Setup

```bash
cd server
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Server starts at `http://localhost:8000`

Open `http://localhost:8000` in your browser — FastAPI serves `client/index.html` automatically.

## API Documentation

FastAPI auto-generates interactive API docs at:
- `http://localhost:8000/docs`     (Swagger UI)
- `http://localhost:8000/redoc`    (ReDoc)

## Database

`cseds.db` (SQLite3) is auto-created on first run in the `server/` directory.

Tables:
- `users`    — username, bcrypt(auth_key), salt, argon2 params
- `blobs`    — encrypted blob per user, server timestamp, version
- `sessions` — single active session token per user

## Production Notes

For production deployment:
- Place behind Caddy (TLS termination, reverse proxy)
- Serve `client/` via Nginx
- Proxy `/api/*` to Uvicorn
- Set `reload=False` in uvicorn.run()
- Consider PostgreSQL for multi-instance deployments

See `DEPLOYMENT.md` (coming soon) for Caddy + Nginx configuration.
