# SOC Supply — Manual

Third-party exposure monitor. You keep a private register of the organisations
you depend on; SOC Supply checks each one's domain against breach intelligence
and tells you which of your suppliers, clients or vendors is compromised.

---

## Your list stays here

This is the design constraint the module is built around.

- **Nothing uploads it.** There is no code path that sends the register to
  soc-intel, to a case tracker, or to any third party. The CI pipeline fails the
  build if a push endpoint ever appears in the source.
- In the **default mode** the only thing the service talks to is your own
  soc-intel instance. Your supplier names and domains never leave the network.
- The banner at the top of the page always tells you which mode you are in:
  green means private, amber means `EXTERNAL_LOOKUPS=1` and each scan sends the
  party's domain to Hudson Rock.
- Import and export are local file operations.
- The database `supply.db` holds the register. Treat it as confidential business
  data — it is gitignored, and it deserves the same care as `soc-ops.db`.

---

## Building the register

**Add one** — fill the form: name and domain are required, the rest is optional.

**Import many** — paste CSV or JSON into the Import box.

```csv
name,domain,category,criticality,contact,notes
Acme Logistics,acme-logistics.example,supplier,high,ops@acme-logistics.example,ships nightly
Beta Consulting,beta.example,vendor,medium,,payroll SaaS
```

The header row is optional; without one the columns are read in the order above.
JSON is a list of the same keys. Import is **idempotent on the domain** — a
domain already present is updated in place, never duplicated, so re-importing a
corrected spreadsheet is safe.

| Field | Values |
|-------|--------|
| `category` | `client` `supplier` `vendor` `partner` `subsidiary` `other` |
| `criticality` | `low` `medium` `high` `critical` |

Anything unrecognised falls back to `other` / `medium` rather than failing the row.
Rows with no name or an unparseable domain are skipped and reported.

**Edit / delete** — the buttons on each row. Deleting a party also deletes its
findings.

---

## Scanning

`scan` on a row checks one party. **Scan all** walks the register — that is one
pass per party, so a large register takes a while.

A background thread rescans everything every `SCAN_INTERVAL_H` hours (24 by
default, `0` disables it), waiting 30 seconds at start-up for soc-intel.

### What is checked

| Kind | Meaning | Severity |
|------|---------|----------|
| `ransomware-leak` | the party appears on a ransomware leak site | critical |
| `credential-exposure` | credentials for the domain in a breach dump | high |
| `stealer-log` | infostealer log naming the domain | high |
| `iab-listing` | an initial-access broker is selling access | high |
| `infostealer` | Hudson Rock Cavalier (external, opt-in) | high |
| `tg-message` | the domain named in a breach Telegram channel | medium |

The `?q=` searches against soc-intel are fuzzy, so results are filtered against
the party's actual domain before being stored. This drops the noise you would
otherwise get from a substring match.

### Findings

Deduplicated on party + kind + reference. Seeing a finding again bumps
`last_seen`; the first sighting is counted as **new** in the scan result. So a
scan reporting `12 finding(s), 0 new` means nothing has changed since last time.

---

## Reading the dashboard

| KPI | Meaning |
|-----|---------|
| Parties | size of the register |
| Exposed | parties with at least one finding |
| High/Critical | findings at those severities, across all parties |
| Findings | every finding, all severities |

A party with no findings shows a green **clean** pill. Treat `clean` as "nothing
in our intel", not "not breached" — absence of evidence.

---

## Triage

1. Sort your attention by **criticality × severity**. A `critical` supplier with
   a `ransomware-leak` finding is the one to call today.
2. Open the finding's `ref` in soc-intel to see the underlying object.
3. `credential-exposure` and `stealer-log` against a supplier who has access to
   your systems means their access should be treated as compromised — rotate the
   credentials on **your** side, do not wait for them.
4. `iab-listing` means someone is selling entry. Assume a short fuse.
5. Record the incident in soc-ir-cases. SOC Supply deliberately does not create
   cases for you — that would mean shipping the register into another system.

---

## Configuration

| Var | Default | Meaning |
|-----|---------|---------|
| `SUPPLY_PORT` | `8109` | listen port |
| `SUPPLY_HOST` | `0.0.0.0` | bind address. Any non-loopback bind is token-gated (HTTP Basic). |
| `SUPPLY_TOKEN` | *(auto)* | password for network access; any username. Blank auto-generates `.supply_token` (0600), shown in the startup log. Loopback binds skip auth. |
| `SUPPLY_DB` | `./supply.db` | SQLite path |
| `EXTERNAL_LOOKUPS` | `0` | `1` adds the Hudson Rock live lookup |
| `SCAN_INTERVAL_H` | `24` | background rescan period; `0` disables |
| `SOCINT_API_URL` | `http://localhost:8000/api` | soc-intel API base |
| `SOCINT_USER` / `SOCINT_PASS` | | soc-intel credentials |

---

## Troubleshooting

**Every party is clean, including ones you know are breached.** soc-intel is
probably unreachable or the credentials are wrong — the client fails closed and
returns nothing. Check `curl $SOCINT_API_URL/health` and the service log.

**A party you deleted still shows findings.** It should not; deletion removes the
findings and scans too. If you re-added the same domain, it is a new party with
an empty history.

**Hudson Rock findings never appear.** They require `EXTERNAL_LOOKUPS=1`. The
banner tells you which mode you are in.

**Import skipped rows.** The message lists the reason for the first 20. Usually a
missing name or a domain that is really a URL with a path.
