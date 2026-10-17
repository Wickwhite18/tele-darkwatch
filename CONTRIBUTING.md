# 🤝 Contributing to tele-darkwatch

Thanks for helping build defensive monitoring tooling! This guide covers setup,
conventions, and how to extend the pipeline safely.

## Development setup

```bash
git clone https://github.com/Wickwhite18/tele-darkwatch.git
cd tele-darkwatch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest              # expect everything green (129+ tests)
ruff check src tests
darkwatch dashboard # poke at the UI locally
```

## Project conventions

- **Offline-first tests.** No test may require network, Tor, Telegram creds, or
  optional heavy deps. HTTP is mocked via `httpx.MockTransport`; adapters for
  Telethon/aiohttp/pytesseract/yara-python must no-op cleanly when absent.
- **Optional integrations live behind extras** (`[telegram]`, `[darkweb]`,
  `[playwright]`, `[ocr]`, `[yara]`). Import them lazily inside functions and
  raise a clear install hint, never an ImportError traceback, at runtime.
- **Everything through the store.** New data sources subclass
  `collectors.base.BaseCollector` and write via `storage.MessageStore` so dedup,
  FTS indexing, retention, and audit logging apply automatically.
- **UI changes go through `ui.py`.** Never print ANSI directly — respect
  `NO_COLOR` / `DW_UI_PLAIN` / non-TTY detection, and keep the plain-mode line
  format stable (tests and log shippers parse it).
- **Machine output stays contract-stable.** If you change rich/table output,
  verify `DW_JSON=1` and plain modes still emit the documented shapes.
- Validate all user input in `validation.py`; surface `ValidationError` as a
  clean `[ERROR] input error: …` line with exit code 2.

## Adding a feature

1. Open an issue first for anything beyond a typo — scope matters here.
2. Branch from `main`: `feat/<short-name>` or `fix/<short-name>`.
3. Write tests alongside code (`tests/test_<area>.py`); aim for the module's
   public API plus its CLI surface if applicable.
4. Update docs in the same PR: README table row(s), `docs/RECIPES.md` if it's a
   workflow, `docs/CONFIG.md` if it adds settings, `.env.example` for new vars.
5. `make test lint` must pass before requesting review.

## Safety & scope boundaries (non-negotiable)

This project is **defensive-only**:

- ✅ Public/lawful sources; read-only token validation; in-memory parsing of
  untrusted artifacts with magic-byte guards; PII masking; audit logging.
- ❌ No account-warming automation, no CAPTCHA-solving integrations, no LLM
  persona engagement with threat actors, no features that facilitate accessing
  or purchasing stolen data.

PRs that push against these boundaries will be closed. When unsure, ask in an
issue before writing code.

## Release checklist

Maintainers bump three places together: `pyproject.toml` version,
`src/tele_darkwatch/__init__.py` `__version__`, and the README badges/footer.
Tag `vX.Y.Z` after CI passes on `main`.

🏠 Back to [README](../README.md)
