# Contributing

Thanks for helping! The short version:

1. Fork, create a branch, make your change.
2. Add or update a test if you changed behaviour.
3. Run the tests (see the README) and make sure they pass.
4. Open a pull request and say what you changed and why.

## Dev setup

```bash
# backend
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests/

# frontend
cd frontend && npm ci && npm test && npm run dev
```

More detail on how the code fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Good first contributions: new crawler signatures, real crawler verification (IP ranges / Web Bot Auth),
Postgres support, dashboard polish, translations, and anything in `docs/KNOWN_LIMITATIONS.md`.

Be kind. We are all just trying to keep the robots out of the pantry.
