"""
CrawlBouncer — Agent Mirror

Optional, per-path setting (turn the feature on with MIRROR_ENABLED=true) that
controls what an *allowed* AI crawler receives on a given page:

    "agent" (default) — CrawlBouncer serves a cleaned, extracted rendition of the
                         page: title + main body only, stripped of nav,
                         ads, scripts, and chrome. Built from the origin
                         page and cached.
    "html"             — the crawler is proxied straight to the real
                         origin page, exactly like normal pass-through.

It only runs after the allow/block rules have already let the
request through; it decides *what format* an allowed crawler receives.

Origin fetches are resolved and pinned via the shared
`ssrf_safe_fetch.resolve_and_pin` helper — see that module for why a
plain "validate, then let the HTTP client resolve DNS again on its
own" check doesn't actually close the SSRF gap it looks like it does.
"""
from __future__ import annotations
import re
import time
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.database import get_db
from app.config import cfg
from app.services.ssrf_safe_fetch import resolve_and_pin, UnsafeURLError

VALID_MODES = {"agent", "html"}
DEFAULT_MODE = "agent"

STRIP_TAGS = {"script", "style", "nav", "header", "footer", "aside", "form", "button", "noscript"}
BLOCK_TAGS = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "br", "div"}


# ─────────────────────────────────────────────────────────────────
# PER-PATH SETTINGS
# ─────────────────────────────────────────────────────────────────

def get_serve_mode(domain_id: str, path: str) -> str:
    """Return the configured serve mode for a path, defaulting to 'agent'."""
    with get_db() as db:
        row = db.execute(
            "SELECT serve_mode FROM mirror_settings WHERE domain_id=? AND path=?",
            (domain_id, path)
        ).fetchone()
    return row["serve_mode"] if row else DEFAULT_MODE


def set_serve_mode(domain_id: str, path: str, mode: str) -> None:
    if mode not in VALID_MODES:
        raise ValueError(f"serve_mode must be one of {sorted(VALID_MODES)}")
    with get_db() as db:
        db.execute("""
            INSERT INTO mirror_settings (domain_id, path, serve_mode, updated_at)
            VALUES (?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(domain_id, path) DO UPDATE SET
                serve_mode = excluded.serve_mode,
                updated_at = CURRENT_TIMESTAMP
        """, (domain_id, path, mode))


def reset_serve_mode(domain_id: str, path: str) -> None:
    """Remove an override, reverting the path to the 'agent' default."""
    with get_db() as db:
        db.execute(
            "DELETE FROM mirror_settings WHERE domain_id=? AND path=?",
            (domain_id, path)
        )


def list_overrides(domain_id: str) -> list[dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT path, serve_mode, updated_at FROM mirror_settings "
            "WHERE domain_id=? ORDER BY path",
            (domain_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────
# LIGHTWEIGHT CONTENT EXTRACTION (stdlib only — no new dependency)
# ─────────────────────────────────────────────────────────────────

class _ArticleExtractor(HTMLParser):
    """
    Best-effort readability-style extraction. Prefers content inside
    <article>, falling back to <main>, falling back to <body>. Keeps
    only block-level text; drops script/style/nav/header/footer/aside.
    Not meant to be perfect — meant to be a clean, honest v1 that can be
    swapped for a dedicated extraction library later without changing
    the public interface (get_or_build_mirror).
    """
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self._skip_depth = 0
        self._container_stack: list[str] = []
        self._in_container_depth = 0
        self._buffer: list[str] = []
        self._h1_seen = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        if tag in STRIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in ("article", "main"):
            self._container_stack.append(tag)
        if tag == "br":
            self._buffer.append("\n")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in STRIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag in ("article", "main") and self._container_stack:
            self._container_stack.pop()
        if tag in BLOCK_TAGS:
            self._buffer.append("\n")

    def handle_data(self, data):
        if self._in_title:
            self.title += data
            return
        if self._skip_depth:
            return
        text = data.strip()
        if text:
            self._buffer.append(text + " ")

    def extracted_text(self) -> str:
        text = "".join(self._buffer)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
        return text.strip()


def _extract_article(html: str) -> tuple[str, str]:
    """Return (title, content_html) extracted from a raw HTML document."""
    parser = _ArticleExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    title = parser.title.strip() or "Untitled"
    text = parser.extracted_text()

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        content_html = "<p><em>No extractable article content was found on this page.</em></p>"
    else:
        content_html = "\n".join(f"<p>{_escape(p)}</p>" for p in paragraphs)

    return title, content_html


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def render_agent_page(title: str, content_html: str, source_url: str) -> str:
    """Wrap extracted content in a minimal, clearly-labeled HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="cb-serve-mode" content="agent">
<link rel="canonical" href="{_escape(source_url)}">
<title>{_escape(title)}</title>
</head>
<body>
<article>
<h1>{_escape(title)}</h1>
{content_html}
</article>
<hr>
<p><small>Served via CrawlBouncer Agent Mirror — a cleaned rendition for AI agents.
Original page: <a href="{_escape(source_url)}">{_escape(source_url)}</a></small></p>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────
# FETCH + CACHE
# ─────────────────────────────────────────────────────────────────

async def _fetch_origin_html(origin_url: str, path: str, query: str = "") -> str:
    try:
        pinned_url, extensions = resolve_and_pin(origin_url)
    except UnsafeURLError as e:
        raise httpx.HTTPError(f"Configured origin is unusable: {e}")

    base   = pinned_url.rstrip("/") + "/"
    target = urljoin(base, path.lstrip("/"))
    if query:
        target = f"{target}?{query}"
    real_hostname = urlparse(origin_url).hostname

    timeout = httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        resp = await client.get(
            target, headers={"x-cb-gateway": "1", "host": real_hostname},
            extensions=extensions,
        )
        resp.raise_for_status()
        return resp.text


async def get_or_build_mirror(domain_id: str, path: str, origin_url: str, query: str = "") -> dict:
    """
    Return {"title", "content_html"} for the Agent Mirror rendition of a
    path, using the cache when fresh and rebuilding it from the origin
    when missing or stale.
    """
    with get_db() as db:
        cached = db.execute(
            "SELECT title, content_html, fetched_at FROM mirror_cache "
            "WHERE domain_id=? AND path=?",
            (domain_id, path)
        ).fetchone()

    if cached:
        fetched_ts = time.mktime(time.strptime(cached["fetched_at"], "%Y-%m-%d %H:%M:%S"))
        if time.time() - fetched_ts < cfg.MIRROR_CACHE_TTL_SECONDS:
            return {"title": cached["title"], "content_html": cached["content_html"]}

    html = await _fetch_origin_html(origin_url, path, query)
    title, content_html = _extract_article(html)

    with get_db() as db:
        db.execute("""
            INSERT INTO mirror_cache (domain_id, path, title, content_html, fetched_at)
            VALUES (?,?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(domain_id, path) DO UPDATE SET
                title = excluded.title,
                content_html = excluded.content_html,
                fetched_at = CURRENT_TIMESTAMP
        """, (domain_id, path, title, content_html))

    return {"title": title, "content_html": content_html}
