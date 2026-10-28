# SentinelX Dashboard

Responsive React + TypeScript + Vite interface for the SentinelX defensive authentication-log lab.

## Run in a browser-based IDE

From this directory:

```bash
npm install
npm run dev
```

Vite binds to `0.0.0.0` for browser IDE preview support. Use the IDE's preview/port-forwarding action to open port 5173.

## Modes

- **Demo mode:** runs the browser-side deterministic synthetic dataset and rule locally. No API or external target is contacted.
- **API mode:** enter the base URL of a running SentinelX API. The UI requests `/health`, `/analyze`, and `/evaluate`. The API must allow the dashboard's exact origin through `SENTINELX_CORS_ORIGINS`.

When detection settings change after connecting, click **Connect** again to refresh the backend snapshot. The dashboard falls back to local synthetic calculations for changed settings until refreshed.

## Build

```bash
npm run build
npm run preview
```

The generated static site is in `dist/`. For Vercel, import the repository and set the project root directory to `dashboard`; use `npm run build` as the build command and `dist` as the output directory.

## Research caveat

The dashboard's metrics are event-level scores against the included synthetic labels. Threshold sweeps are exploratory on the same dataset and are not a held-out benchmark or a claim of production detection efficacy.
