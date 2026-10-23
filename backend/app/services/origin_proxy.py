"""Safe upstream proxying for protected publisher domains."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import Response

from app.services.ssrf_safe_fetch import resolve_and_pin, UnsafeURLError

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


def _target_path(pinned_url: str, request: Request) -> str:
    base = pinned_url.rstrip("/") + "/"
    target = urljoin(base, request.url.path.lstrip("/"))
    return f"{target}?{request.url.query}" if request.url.query else target


async def proxy_to_origin(request: Request, origin_url: str) -> Response:
    """Forward one approved request to a public publisher origin.

    Resolution and validation happen once, via resolve_and_pin — see
    ssrf_safe_fetch.py for why the actual connection is pinned to that
    one validated address rather than letting httpx re-resolve DNS on
    its own moments later.
    """
    try:
        pinned_url, extensions = resolve_and_pin(origin_url)
    except UnsafeURLError as e:
        raise HTTPException(502, f"Configured origin is unusable: {e}")

    real_hostname = urlparse(origin_url).hostname
    forwarded_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS | {"host", "x-domain-id"}
    }
    forwarded_headers["host"] = real_hostname
    forwarded_headers["x-forwarded-proto"] = request.url.scheme
    forwarded_headers["x-cb-gateway"] = "1"
    timeout = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            upstream = await client.request(
                request.method, _target_path(pinned_url, request),
                headers=forwarded_headers, content=await request.body(),
                extensions=extensions,
            )
    except httpx.HTTPError:
        raise HTTPException(502, "Publisher origin is unavailable")
    headers = {
        key: value for key, value in upstream.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS | {"content-length"}
    }
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)
