# Bolt-on integration snippets

Use these when you want to **keep your existing CDN/proxy/app server** instead of
sending traffic through CrawlBouncer. Your own server calls `POST /v1/decide`
before serving each request and enforces the answer.

Add a domain in **bolt-on** mode in the dashboard; it shows an edge key once.
Keep that key on your server. Never put it in browser code.

The answer is JSON: `{"action": "allow" | "block", ...}`

| action    | what you should do                                                    |
|-----------|-----------------------------------------------------------------------|
| `allow`   | serve the real page                                                   |
| `block`   | refuse the request (403)                                              |

Bolt-on mode only classifies **named AI crawlers**. WAF, rate limiting and general
bot defence stay your CDN's job (or use reverse-proxy mode).

## `node/`: Node / Express

`cbMiddleware.js` calls `/v1/decide` and acts on the result.
See `example-app.js` for the wiring. Run its tests with:

```bash
node --test node/cbMiddleware.test.js
```

## `nginx-njs/`: Nginx

nginx can only branch on HTTP status codes, but `/v1/decide` always answers 200
with the decision in the JSON body. `cb_decide.js` uses `njs` (nginx's JavaScript
module) to read the JSON and act on it. Read the comment at the top of the file
first. Needs `ngx_http_js_module` (on Debian/Ubuntu: `apt install libnginx-mod-http-js`).

> Honest note: the Node middleware has automated tests; the nginx/njs script
> does not. Try it on a staging server before trusting it.

## Fail-open or fail-closed?

Both integrations **fail closed** (403/503) if CrawlBouncer is unreachable, unless you
opt into `failOpen`. Closed blocks legitimate crawlers during an outage; open lets
everything through (including blocked crawlers). Pick on purpose.
