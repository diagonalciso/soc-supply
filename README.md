# soc-supply

Third-party / supply-chain exposure monitor. Keep a **private register** of the
organisations you depend on — clients, suppliers, vendors, partners — and check
each one's domain for breach exposure. Part of the CD SOC suite. Port **8109**.

Self-contained, **stdlib-only** — no pip dependencies.

## Privacy — the point of the module

The register never leaves this host.

- **No upload path exists.** This service does not POST to soc-intel
  `/intel/bulk`, does not create cases, and has no export-to-network code. CI
  asserts the source contains no push endpoint.
- **Default (`EXTERNAL_LOOKUPS=0`)**: the only host contacted is your own
  self-hosted **soc-intel**, whose darkweb store already holds the breach corpus.
  Nothing about the register reaches a third party.
- **`EXTERNAL_LOOKUPS=1`** adds a live Hudson Rock infostealer query per domain
  (proxied through soc-intel, but the domain does reach Hudson Rock). Opt-in
  only — same idiom as `ACTIVE_PROBES` in soc-osint.
- Import and export read and write **local files only**.
- `supply.db` is gitignored. Back it up like any other sensitive SOC database.

The UI binds `0.0.0.0` so analysts can reach it across the SOC LAN. Because the
register is confidential, **any non-loopback bind is gated by a token** (HTTP Basic:
any username, the token as the password). Set `SUPPLY_TOKEN`, or leave it blank and a
token is generated on first boot (persisted to `.supply_token`, printed in the log).
A loopback bind (`SUPPLY_HOST=127.0.0.1`) skips auth for local-only use. `/health` is
always open so the hub can probe it. This is the one guarantee the code enforces on
both sides — the CI build fails if a network bind could ever serve the register
unauthenticated, mirroring the no-upload guard.

## Sources

| Source | Kind | Where it runs |
|--------|------|---------------|
| soc-intel `/darkweb/credentials` | `credential-exposure` | self-hosted |
| soc-intel `/darkweb/objects?type=stealer-log` | `stealer-log` | self-hosted |
| soc-intel `/darkweb/objects?type=iab-listing` | `iab-listing` | self-hosted |
| soc-intel `/darkweb/objects?type=ransomware-leak` | `ransomware-leak` | self-hosted |
| soc-intel `/darkweb/objects?type=tg-message` | `tg-message` | self-hosted |
| soc-intel `/enrich/hudsonrock/domain/` | `infostealer` | **external, opt-in** |

`?q=`-searched types are fuzzy `multi_match` on the soc-intel side, so results are
post-filtered against the party's real domain before they are stored. Telegram
posts carry no structured domain field and are matched on the message text.

Severity: `ransomware-leak` → critical; `credential-exposure`, `stealer-log`,
`iab-listing`, `infostealer` → high; `tg-message` → medium.

## Register

Add, edit and delete parties in the UI. Bulk import accepts either a CSV or a
JSON list; import is **idempotent on `domain`** — a domain already in the
register is updated rather than duplicated.

```csv
name,domain,category,criticality,contact,notes
Acme Logistics,acme-logistics.example,supplier,high,ops@acme-logistics.example,ships nightly
Beta Consulting,beta.example,vendor,medium,,payroll SaaS
```

Header row optional. Categories: `client supplier vendor partner subsidiary other`.
Criticalities: `low medium high critical`. Unknown values fall back to `other` /
`medium`. Export with **Export CSV** / **Export JSON**.

## Scanning

- **Scan** on a row scans one party; **Scan all** walks the register.
- A background thread rescans everything every `SCAN_INTERVAL_H` hours (default
  24; set `0` to disable). It waits 30 s at boot for soc-intel.
- Findings are deduplicated on `(party, kind, ref)`. Re-seeing a finding bumps
  `last_seen`; first sighting counts as **new**.

## Configure

```bash
cp .env.example .env
python3 app.py
```

| Var | Default | Meaning |
|-----|---------|---------|
| `SUPPLY_PORT` | `8109` | listen port |
| `SUPPLY_HOST` | `0.0.0.0` | bind address. Non-loopback binds require the token. |
| `SUPPLY_TOKEN` | *(auto)* | HTTP Basic password for network access; blank = auto-generate to `.supply_token` |
| `SUPPLY_DB` | `./supply.db` | SQLite path |
| `EXTERNAL_LOOKUPS` | `0` | `1` enables the Hudson Rock live lookup |
| `SCAN_INTERVAL_H` | `24` | background rescan period; `0` disables |
| `SOCINT_API_URL` | `http://localhost:8000/api` | soc-intel API |
| `SOCINT_USER` / `SOCINT_PASS` | — | soc-intel credentials |

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/parties` | register |
| GET | `/api/findings[?party_id=N]` | exposure findings |
| GET | `/api/stats` | KPIs |
| GET | `/api/export?fmt=csv\|json` | download the register |
| POST | `/api/party/add` | JSON body |
| POST | `/api/party/update?id=N` | JSON body |
| POST | `/api/party/delete?id=N` | also drops its findings |
| POST | `/api/import` | CSV or JSON body |
| POST | `/api/scan?id=N` \| `?all=1` | scan one / all |
| GET | `/health` | liveness |
| GET | `/manual` | rendered `MANUAL.md` |

## Licence

MIT.
