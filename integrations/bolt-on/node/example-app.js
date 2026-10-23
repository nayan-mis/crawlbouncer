// Minimal example — not a real server, just shows the wiring.
const express = require('express');
const { cbBoltOn } = require('./cbMiddleware');

const app = express();

app.use(cbBoltOn({
    edgeKey: process.env.CB_EDGE_KEY,       // shown once when you added this domain as bolt-on
    apiBase: process.env.CB_API_BASE,       // optional, defaults to http://localhost:8000
    failOpen: false,                          // see cbMiddleware.js — this is a real product decision
}));

app.get('*', (req, res) => {
    res.send(`Real content for ${req.path} — a human or a paying crawler got here.`);
});

app.listen(8080, () => console.log('Origin listening on :8080, gated by CrawlBouncer bolt-on middleware'));
