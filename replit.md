# Chain-Mind Auditor on Replit

## Run the web app

Use the **Run** button. The `Start application` workflow runs:

```bash
python main.py web --host 0.0.0.0 --port 5000
```

The browser workspace is available at `/`, with API documentation at `/docs`.

## Optional live-service configuration

The application works without credentials in offline heuristic and simulated
mempool modes. Live features can use Replit Secrets for `GEMINI_API_KEY`,
`ETHERSCAN_API_KEY`, and provider-specific RPC URLs documented in `README.md`.

Before exposing the app publicly, set `CHAINMIND_ADMIN_PASSCODE` to replace the
development default used by the Settings area.