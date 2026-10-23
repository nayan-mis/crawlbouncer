# Security policy

Please **do not open a public issue** for a security problem. Use GitHub's
"Report a vulnerability" button (Security tab) on this repository instead, and include steps to reproduce.

Things worth knowing before you deploy:

- Set a real `JWT_SECRET` and `ENV=production`. Production mode refuses to start with unsafe settings.
- Put HTTPS in front (see `deploy/Caddyfile.example`).
- Signups are closed after the first account by default. Keep it that way unless you mean it.
- The bolt-on edge key identifies a domain. Keep it on your server, never in browser code.
