/**
 * CrawlBouncer — bolt-on integration middleware for Node/Express.
 *
 * Unlike the Nginx path (see ../nginx-njs/), this needs no bridging —
 * Node can read /v1/decide's JSON response directly and act on the
 * `action` field itself. Call this before your real route handlers.
 *
 * Usage:
 *   const { cbBoltOn } = require('./cbMiddleware');
 *   app.use(cbBoltOn({
 *     edgeKey: process.env.CB_EDGE_KEY,
 *   }));
 *
 * On "allow" it just calls next(). On "block" it ends the request with
 * 403.
 */

function cbBoltOn({ edgeKey, apiBase = 'http://localhost:8000', timeoutMs = 3000, failOpen = false } = {}) {
    if (!edgeKey) {
        throw new Error('cbBoltOn: edgeKey is required (the key shown once when you added this domain as bolt-on)');
    }

    return async function (req, res, next) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const response = await fetch(`${apiBase}/v1/decide`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Edge-Key': edgeKey,
                },
                body: JSON.stringify({
                    path: req.path,
                    user_agent: req.get('user-agent') || '',
                    ip: req.ip || '',
                }),
                signal: controller.signal,
            });

            if (!response.ok) {
                // CrawlBouncer itself is unreachable or erroring. failOpen is a real
                // product decision, not a default to take lightly: failing
                // open serves everything (even blocked crawlers) during an outage; failing
                // closed blocks legitimate crawlers (and, if bot detection
                // ever misfires on a human, real visitors) until it recovers.
                if (failOpen) return next();
                return res.status(503).json({ error: 'CrawlBouncer decision service unavailable' });
            }

            const decision = await response.json();

            switch (decision.action) {
                case 'allow':
                    return next();

                case 'block':
                    return res.status(403).json({
                        status: 403,
                        message: 'Access denied by CrawlBouncer bot policy.',
                    });

                default:
                    // Unrecognized action — fail closed rather than guess.
                    return res.status(502).json({ error: 'Unrecognized decision from CrawlBouncer' });
            }
        } catch (err) {
            if (failOpen) return next();
            return res.status(503).json({ error: 'CrawlBouncer decision service unreachable', detail: err.message });
        } finally {
            clearTimeout(timeout);
        }
    };
}

module.exports = { cbBoltOn };
