# Known limitations

Honest list. If something here matters to you, it is also a good first contribution.

## Security model

- **Crawlers are recognised by User-Agent only.** A scraper can lie. Today `allow`
  means "treated like any normal visitor", so a faker gains nothing extra, but a `block`
  rule can be dodged by a bot that does not announce itself. Real verification
  (published IP ranges, reverse DNS, or the HTTP Message Signatures / "Web Bot Auth"
  standard) is not implemented yet.
- **`Google-Extended` and `Applebot-Extended` are robots.txt tokens**, not User-Agents. They can only be
  controlled through the generated `robots.txt` (the dashboard marks them "robots.txt only").
- **Unknown bots** (curl, headless browsers, scripts) are handled by the generic risk/rate-limit
  ladder, not by per-crawler rules.
- **Bolt-on mode** only classifies named AI crawlers; WAF, rate limiting and flood protection are not
  applied. That is by design (your CDN does that), but know it.

## Scaling and operations

- **SQLite, one process.** Fine for a single server. Rate-limit counters, the rule cache and the
  anomaly detector live in process memory, so run **one worker**. Several workers or several
  servers would each keep their own state.
- **No HTTPS built in.** Use Caddy or Cloudflare in front.
- **Raw request logs** are pruned after `DATA_RETENTION_DAYS` (default 90).
- **No built-in backups.** Copy the SQLite file (`/app/data/crawlbouncer.db` in Docker).

## Product gaps

- Dashboard "Crawlers" request counts are totals across all your domains, not per selected domain.
- CrawlBouncer does not issue or manage TLS certificates (use Caddy or Cloudflare in front).
- Password reset works for owner accounts only, not invited team members.
- The Agent Mirror is experimental and off by default.
- English only. No mobile app. The dashboard is usable on a phone, not optimised for one.

## Testing

- The nginx/njs bolt-on script has no automated tests.
- Dependency versions are ranges, not pinned. After your first successful install, run
  `pip freeze > requirements.lock` and commit it; run `pip-audit` occasionally.
