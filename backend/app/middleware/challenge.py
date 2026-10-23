"""
CrawlBouncer — Challenge Middleware
Serves a challenge page to suspicious traffic instead of blocking outright.
Two challenge types:
  1. Proof-of-Work   — browser computes SHA-256 hash (bots without JS fail)
  2. hCaptcha        — CAPTCHA for ambiguous human/bot traffic
On pass: issues a signed session cookie valid for 1 hour.
On future requests: cookie is verified, challenge bypassed.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import cfg
from app.services.client_ip import get_client_ip

# ─────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────

CHALLENGE_COOKIE   = "cb_challenge"
COOKIE_VALID_SECS  = 3600          # 1 hour
POW_DIFFICULTY     = 4             # leading zeros required in SHA-256 hash
HCAPTCHA_SECRET    = os.getenv("HCAPTCHA_SECRET_KEY", "")
HCAPTCHA_SITEKEY   = os.getenv("HCAPTCHA_SITE_KEY", "10000000-ffff-ffff-ffff-000000000001")  # test key


# ─────────────────────────────────────────────────────────────────
# COOKIE — sign / verify
# ─────────────────────────────────────────────────────────────────

def _sign_cookie(ip: str) -> str:
    """Issue a signed challenge pass cookie for an IP."""
    issued_at = int(time.time())
    payload   = f"{ip}:{issued_at}"
    sig       = hmac.new(cfg.JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def verify_cookie(cookie_value: str, ip: str) -> bool:
    """
    Verify a challenge pass cookie.
    Returns True if the cookie is valid and not expired.
    """
    if not cookie_value:
        return False
    try:
        parts = cookie_value.split(":")
        if len(parts) != 3:
            return False
        cookie_ip, issued_str, provided_sig = parts
        if cookie_ip != ip:
            return False
        issued_at = int(issued_str)
        if time.time() - issued_at > COOKIE_VALID_SECS:
            return False
        payload  = f"{cookie_ip}:{issued_str}"
        expected = hmac.new(cfg.JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(expected, provided_sig)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# PROOF-OF-WORK VERIFICATION (server side)
# ─────────────────────────────────────────────────────────────────

def verify_pow(nonce: str, solution: str, difficulty: int = POW_DIFFICULTY) -> bool:
    """
    Verify a proof-of-work solution submitted by the browser.
    The browser must find `solution` such that:
      SHA256(nonce + solution) starts with `difficulty` leading zeros.
    """
    try:
        candidate = hashlib.sha256(f"{nonce}{solution}".encode()).hexdigest()
        return candidate.startswith("0" * difficulty)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# HCAPTCHA VERIFICATION (server side)
# ─────────────────────────────────────────────────────────────────

def verify_hcaptcha(token: str) -> bool:
    """
    Verify an hCaptcha response token with the hCaptcha API.
    Returns True if valid. Falls back to True in development.
    """
    if cfg.is_development:
        return True                  # skip real verification in dev
    if not HCAPTCHA_SECRET or not token:
        return False
    try:
        payload = f"secret={HCAPTCHA_SECRET}&response={token}".encode()
        req     = urllib.request.Request(
            "https://hcaptcha.com/siteverify",
            data=payload,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return data.get("success", False)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# CHALLENGE PAGES (HTML)
# ─────────────────────────────────────────────────────────────────

def pow_challenge_page(nonce: str, return_path: str) -> str:
    """
    Returns an HTML page that runs a JS proof-of-work challenge.
    The browser computes a SHA-256 hash and POSTs the solution.
    Automated scripts without a JS engine cannot complete this.
    """
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>One moment — CrawlBouncer</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0A0A0A;--surface:#111111;--border:#1F1F1F;
  --t1:#F5F5F5;--t2:#A1A1AA;--t3:#52525B;
  --green:#22C55E;--green-bg:rgba(34,197,94,.08);
  --font:'Inter',-apple-system,sans-serif;
}}
[data-theme="light"]{{
  --bg:#FFFFFF;--surface:#FAFAFA;--border:#E8E8E8;
  --t1:#0A0A0A;--t2:#6B6B6B;--t3:#AEAEAE;
}}
body{{background:var(--bg);color:var(--t1);font-family:var(--font);
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  -webkit-font-smoothing:antialiased}}
.card{{border:1px solid var(--border);border-radius:8px;padding:32px 36px;
  width:380px;max-width:calc(100vw - 32px);background:var(--surface);
  display:flex;flex-direction:column;align-items:center;gap:20px;text-align:center}}
.logo{{width:32px;height:32px;background:var(--t1);border-radius:6px;
  display:flex;align-items:center;justify-content:center}}
.logo svg{{width:16px;height:16px;fill:var(--bg)}}
.title{{font-size:15px;font-weight:600;color:var(--t1)}}
.sub{{font-size:12.5px;color:var(--t2);line-height:1.6;max-width:280px}}
.progress{{width:100%;height:3px;background:var(--border);border-radius:2px;overflow:hidden}}
.bar{{height:100%;width:0%;background:var(--t1);border-radius:2px;transition:width .1s linear}}
.status{{font-size:11.5px;color:var(--t3);min-height:18px}}
.check{{width:40px;height:40px;border:1.5px solid var(--green);border-radius:50%;
  display:none;align-items:center;justify-content:center}}
.check svg{{width:18px;height:18px;color:var(--green)}}
.cb-credit{{font-size:11px;color:var(--t3);margin-top:4px}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 10 10"><path d="M1 2h8M1 5h5M1 8h7"/><circle cx="8" cy="8" r="1.5" fill="var(--bg)"/></svg>
  </div>
  <div>
    <div class="title">Checking your browser</div>
    <div class="sub" style="margin-top:6px">This takes less than a second. You will be redirected automatically.</div>
  </div>
  <div class="progress"><div class="bar" id="bar"></div></div>
  <div class="status" id="status">Starting verification…</div>
  <div class="check" id="check">
    <svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="3,9 7,13 15,5"/>
    </svg>
  </div>
  <div class="cb-credit">Protected by CrawlBouncer</div>
</div>

<script>
(async function() {{
  const NONCE      = "{nonce}";
  const DIFFICULTY = {POW_DIFFICULTY};
  const RETURN     = "{return_path}";

  const bar    = document.getElementById('bar');
  const status = document.getElementById('status');
  const check  = document.getElementById('check');

  async function sha256(msg) {{
    const buf = new TextEncoder().encode(msg);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  }}

  const prefix = '0'.repeat(DIFFICULTY);
  let candidate = 0;
  const start   = performance.now();

  while (true) {{
    const sol   = candidate.toString(36);
    const hash  = await sha256(NONCE + sol);

    if (hash.startsWith(prefix)) {{
      // Solution found — submit to server
      status.textContent = 'Verification complete.';
      bar.style.width    = '100%';
      check.style.display = 'flex';

      const form = document.createElement('form');
      form.method = 'POST';
      form.action = '/challenge/verify';
      [['nonce', NONCE], ['solution', sol], ['return', RETURN]].forEach(([k,v]) => {{
        const i = document.createElement('input');
        i.type = 'hidden'; i.name = k; i.value = v;
        form.appendChild(i);
      }});
      document.body.appendChild(form);
      setTimeout(() => form.submit(), 400);
      return;
    }}

    candidate++;
    if (candidate % 5000 === 0) {{
      const elapsed  = (performance.now() - start) / 1000;
      const progress = Math.min(95, candidate / 80000 * 100);
      bar.style.width    = progress + '%';
      status.textContent = `Computing… (${{candidate.toLocaleString()}} attempts)`;
      await new Promise(r => setTimeout(r, 0)); // yield to browser
    }}
  }}
}})();
</script>
</body>
</html>"""


def hcaptcha_challenge_page(return_path: str) -> str:
    """
    Returns an HTML page showing an hCaptcha widget.
    Used for traffic that passed JS but is still ambiguous.
    """
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Verify — CrawlBouncer</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0A0A0A;--surface:#111111;--border:#1F1F1F;
  --t1:#F5F5F5;--t2:#A1A1AA;--t3:#52525B;
  --font:'Inter',-apple-system,sans-serif;
}}
body{{background:var(--bg);color:var(--t1);font-family:var(--font);
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  -webkit-font-smoothing:antialiased}}
.card{{border:1px solid var(--border);border-radius:8px;padding:32px 36px;
  width:380px;max-width:calc(100vw - 32px);background:var(--surface);
  display:flex;flex-direction:column;align-items:center;gap:20px;text-align:center}}
.logo{{width:32px;height:32px;background:var(--t1);border-radius:6px;
  display:flex;align-items:center;justify-content:center}}
.logo svg{{width:16px;height:16px;fill:var(--bg)}}
.title{{font-size:15px;font-weight:600}}
.sub{{font-size:12.5px;color:var(--t2);line-height:1.6;max-width:280px}}
.btn{{background:var(--t1);color:var(--bg);border:none;border-radius:5px;
  padding:9px 24px;font-size:13px;font-weight:500;cursor:pointer;
  font-family:var(--font);transition:opacity .15s;margin-top:4px}}
.btn:hover{{opacity:.85}}
.cb-credit{{font-size:11px;color:var(--t3)}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 10 10"><path d="M1 2h8M1 5h5M1 8h7"/><circle cx="8" cy="8" r="1.5" fill="var(--bg)"/></svg>
  </div>
  <div>
    <div class="title">One quick check</div>
    <div class="sub" style="margin-top:6px">Please confirm you are human to continue.</div>
  </div>
  <form method="POST" action="/challenge/captcha/verify" id="captcha-form">
    <input type="hidden" name="return" value="{return_path}"/>
    <div class="h-captcha"
         data-sitekey="{HCAPTCHA_SITEKEY}"
         data-callback="onCaptchaPass"
         data-theme="dark">
    </div>
  </form>
  <div class="cb-credit">Protected by CrawlBouncer</div>
</div>
<script>
function onCaptchaPass(token) {{
  const form = document.getElementById('captcha-form');
  const inp  = document.createElement('input');
  inp.type = 'hidden'; inp.name = 'h-captcha-response'; inp.value = token;
  form.appendChild(inp);
  form.submit();
}}
</script>
</body>
</html>"""


def blocked_page(reason: str = "Access denied") -> str:
    """
    Clean block page shown when a request is definitively blocked.
    Never reveals which rule fired.
    """
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Access denied — CrawlBouncer</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0A0A0A;--surface:#111111;--border:#1F1F1F;--t1:#F5F5F5;--t2:#A1A1AA;--t3:#52525B;--red:#F87171;--red-bg:rgba(248,113,113,.08);--font:'Inter',-apple-system,sans-serif}}
body{{background:var(--bg);color:var(--t1);font-family:var(--font);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}}
.card{{border:1px solid var(--border);border-radius:8px;padding:32px 36px;width:380px;max-width:calc(100vw - 32px);background:var(--surface);text-align:center;display:flex;flex-direction:column;align-items:center;gap:16px}}
.icon{{width:36px;height:36px;border:1.5px solid var(--red);border-radius:50%;display:flex;align-items:center;justify-content:center}}
.icon svg{{width:15px;height:15px;color:var(--red)}}
.title{{font-size:15px;font-weight:600}}
.sub{{font-size:12.5px;color:var(--t2);line-height:1.6}}
.code{{font-size:11px;color:var(--t3);font-family:monospace}}
.cb-credit{{font-size:11px;color:var(--t3)}}
</style>
</head>
<body>
<div class="card">
  <div class="icon">
    <svg viewBox="0 0 15 15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
      <line x1="1" y1="1" x2="14" y2="14"/><line x1="14" y1="1" x2="1" y2="14"/>
    </svg>
  </div>
  <div class="title">Access denied</div>
  <div class="sub">Your request was blocked by CrawlBouncer' security filters.</div>
  <div class="code">Reference: {int(time.time())}</div>
  <div class="cb-credit">Protected by CrawlBouncer</div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────
# FASTAPI ROUTES
# Add these to main.py
# ─────────────────────────────────────────────────────────────────

def _record_challenge_event(ip: str, challenge_type: str, passed: bool):
    """Persist a challenge outcome — feeds the anomaly detector's
    challenge_fail_rate feature. Best-effort: a logging failure must
    never block the actual challenge flow."""
    try:
        from app.database import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO challenge_events (ip, challenge_type, passed) VALUES (?,?,?)",
                (ip, challenge_type, int(passed))
            )
    except Exception as e:
        print(f"[Challenge] Failed to record outcome: {e}")


def register_challenge_routes(app):
    """Register challenge verification endpoints on the FastAPI app."""
    import secrets

    @app.get("/challenge/pow")
    async def serve_pow_challenge(request: Request):
        """Serve the proof-of-work challenge page."""
        nonce       = secrets.token_hex(16)
        return_path = request.query_params.get("return", "/")
        return HTMLResponse(pow_challenge_page(nonce, return_path))

    @app.post("/challenge/verify")
    async def verify_pow_challenge(request: Request):
        """Verify a submitted proof-of-work solution."""
        form        = await request.form()
        nonce       = form.get("nonce", "")
        solution    = form.get("solution", "")
        return_path = form.get("return", "/")
        # get_client_ip only trusts X-Real-IP/X-Forwarded-For from a
        # configured trusted proxy (see client_ip.py) — the previous
        # version here read X-Real-IP directly from any caller, which
        # let anyone sign a challenge-pass cookie for an arbitrary IP
        # of their choosing, and poison challenge_events (consumed by
        # anomaly_detector.py's challenge_fail_rate feature) for a
        # third party's real IP.
        ip          = get_client_ip(request)

        if verify_pow(nonce, solution):
            _record_challenge_event(ip, "pow", passed=True)
            cookie = _sign_cookie(ip)
            resp   = RedirectResponse(url=return_path, status_code=302)
            resp.set_cookie(
                key=CHALLENGE_COOKIE, value=cookie,
                max_age=COOKIE_VALID_SECS, httponly=True, samesite="lax",
                secure=cfg.is_production,
            )
            return resp
        else:
            _record_challenge_event(ip, "pow", passed=False)
            return HTMLResponse("<h1>Verification failed. Please go back and try again.</h1>", status_code=400)

    @app.get("/challenge/captcha")
    async def serve_captcha(request: Request):
        """Serve the hCaptcha challenge page."""
        return_path = request.query_params.get("return", "/")
        return HTMLResponse(hcaptcha_challenge_page(return_path))

    @app.post("/challenge/captcha/verify")
    async def verify_captcha_challenge(request: Request):
        """Verify a submitted hCaptcha token."""
        form        = await request.form()
        token       = form.get("h-captcha-response", "")
        return_path = form.get("return", "/")
        ip          = get_client_ip(request)

        if verify_hcaptcha(token):
            _record_challenge_event(ip, "captcha", passed=True)
            cookie = _sign_cookie(ip)
            resp   = RedirectResponse(url=return_path, status_code=302)
            resp.set_cookie(
                key=CHALLENGE_COOKIE, value=cookie,
                max_age=COOKIE_VALID_SECS, httponly=True, samesite="lax",
                secure=cfg.is_production,
            )
            return resp
        else:
            _record_challenge_event(ip, "captcha", passed=False)
            return HTMLResponse(hcaptcha_challenge_page(return_path), status_code=400)
