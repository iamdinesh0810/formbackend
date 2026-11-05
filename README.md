# Swiss form backend (MVP)

Point an HTML form at `POST /submit` with an API key; get email, webhook, dashboard and CSV export.

## Run
```
cp .env.example .env   # edit values
npm install
export $(grep -v '^#' .env | xargs) && npm start
```
Or Docker: `docker build -t formbackend . && docker run -p 3000:3000 --env-file .env -v $(pwd)/data:/app/data formbackend`

Open `/admin`, create a form, paste the embed code into any site.

## Included
API-key endpoint, honeypot (`_gotcha`), per-IP rate limit, domain allow-list, monthly quota,
email (any SMTP), webhook, redirect, dashboard, CSV export (formula-injection safe), hashed IPs.

## Not yet built (next steps)
Customer sign-up and login, Stripe/TWINT billing, per-customer plans, file uploads,
captcha (Turnstile/Altcha), Slack/Discord, auto-responders, Google Sheets, password reset,
delivery retries/queue, abuse reporting, a proper landing page.

## Switzerland checklist
- Host in CH (Infomaniak, Exoscale, Hostpoint) and use a Swiss SMTP provider: your main selling point.
- Impressum, Datenschutzerklärung (revDSG/nDSG), AGB; a DPA for business customers.
- Register a business entity (Einzelfirma/GmbH); VAT is required above CHF 100k turnover.
- Add rate limits at the reverse proxy (Caddy/nginx) and serve over HTTPS only.
