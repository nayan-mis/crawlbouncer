/**
 * CrawlBouncer — bolt-on integration, njs bridge for stock Nginx.
 *
 * WHY THIS FILE EXISTS:
 * CrawlBouncer's POST /v1/decide always answers with HTTP 200 — the actual
 * decision ("allow" / "block") lives inside the JSON body,
 * not the status code. Nginx's built-in directives can't parse JSON
 * body content on their own, so this uses `njs` (nginx's own
 * JavaScript module, ngx_http_js_module) to make the real call, read
 * the JSON, and act on it directly.
 *
 * This uses `js_content` + `ngx.fetch()`. An earlier version tried
 * `js_access` (the pattern nginx.org's own njs reference documents for
 * "check with an external service before allowing a request") plus
 * falling through to `proxy_pass` on allow — verified against a real
 * nginx+njs instance and found the installed module build (Ubuntu's
 * `libnginx-mod-http-js`, njs 0.8.2) doesn't actually export the
 * `js_access` directive (confirmed by inspecting the compiled
 * module's exported directive strings, not assumed from version
 * numbers). `js_content` is universally available, so this uses that
 * plus `r.internalRedirect()` to a named location for the "allow"
 * case, since a `js_content` handler must produce the whole response
 * itself rather than falling through to another directive.
 *
 * A version before that used `r.subrequest()` to an internal
 * `proxy_pass` location plus `auth_request`/`error_page` to relay the
 * result — also verified against a real instance and found NOT to
 * work: `reply.responseBody` came back `undefined` even though the
 * subrequest's status was a correct 200, a known rough edge of
 * capturing subrequest bodies through `proxy_pass` targets in njs.
 * `ngx.fetch()` doesn't have that problem and needs no internal
 * upstream location, no `auth_request_set` variable relay, and no
 * `error_page` dance — `r.return(status, body)` sets the real
 * response directly.
 *
 * Requires: nginx built/packaged with ngx_http_js_module — on
 * Debian/Ubuntu, `apt install libnginx-mod-http-js` (NOT
 * "nginx-module-njs", which doesn't exist as a package name on
 * current Debian/Ubuntu — found by testing, not assumed).
 */

async function decide(r) {
    const edgeKey = r.variables.cb_edge_key;
    const apiBase = r.variables.cb_api_base || 'http://127.0.0.1:8000';

    if (!edgeKey) {
        r.error('cb_decide: cb_edge_key not set');
        r.return(500);
        return;
    }

    let reply;
    try {
        reply = await ngx.fetch(`${apiBase}/v1/decide`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Edge-Key': edgeKey,
            },
            body: JSON.stringify({
                path: r.variables.request_uri,
                user_agent: r.variables.http_user_agent || '',
                ip: r.variables.remote_addr || '',
            }),
        });
    } catch (e) {
        // CrawlBouncer itself unreachable/erroring. Failing closed (403) is the
        // safer default for an access gate than silently allowing
        // everything through during an outage — a publisher who wants
        // fail-open behavior instead should change this explicitly, the
        // same trade-off documented in the Node/Express middleware.
        r.error(`cb_decide: fetch failed — ${e}`);
        r.return(502);
        return;
    }

    if (reply.status !== 200) {
        r.error(`cb_decide: upstream returned ${reply.status}`);
        r.return(502);
        return;
    }

    let decision;
    try {
        decision = await reply.json();
    } catch (e) {
        r.error(`cb_decide: could not parse response — ${e}`);
        r.return(502);
        return;
    }

    if (decision.action === 'allow') {
        // js_content must produce the whole response itself — it can't
        // "fall through" to proxy_pass the way js_access can. The
        // standard pattern for "allow, then let a normal location serve
        // it" is an internal redirect to a named location that does the
        // real proxy_pass.
        r.internalRedirect('@cb_origin');
        return;
    }

    if (decision.action === 'block') {
        r.return(403, JSON.stringify({
            status: 403,
            message: 'Access denied by CrawlBouncer bot policy.',
        }));
        return;
    }

    // Unrecognised action: fail closed rather than guess.
    r.return(502, JSON.stringify({ error: 'Unrecognized decision from CrawlBouncer' }));
}

export default { decide };
