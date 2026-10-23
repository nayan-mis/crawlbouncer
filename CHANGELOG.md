# Changelog

## 0.1.0: first open-source release

- Self-hosted gateway for AI crawlers: `allow` or `block`, per crawler and per path
- Reverse-proxy mode and bolt-on mode (`POST /v1/decide`)
- Web firewall, rate limiting, flood detection, IP reputation, optional anomaly detection
- Dashboard, robots.txt generator, optional Agent Mirror
- Two-factor login, team members, audit log
- Safer defaults: closed signups after the first account, random secret if none set,
  reset tokens never returned by the API
