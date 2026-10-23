const test = require('node:test');
const assert = require('node:assert');
const { cbBoltOn } = require('./cbMiddleware');

function mockReqRes(overrides = {}) {
    const req = {
        path: '/article/test',
        ip: '1.2.3.4',
        get: (h) => (h === 'user-agent' ? 'GPTBot/1.0' : undefined),
        ...overrides,
    };
    const res = {
        _status: null,
        _body: null,
        status(code) { this._status = code; return this; },
        json(body) { this._body = body; return this; },
    };
    return { req, res };
}

test('allow: calls next(), no response written', async () => {
    global.fetch = async () => ({ ok: true, json: async () => ({ action: 'allow', is_bot: true }) });
    const mw = cbBoltOn({ edgeKey: 'test-key' });
    const { req, res } = mockReqRes();
    let nextCalled = false;
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(res._status, null);
});

test('block: responds 403, does not call next()', async () => {
    global.fetch = async () => ({ ok: true, json: async () => ({ action: 'block', is_bot: true }) });
    const mw = cbBoltOn({ edgeKey: 'test-key' });
    const { req, res } = mockReqRes();
    let nextCalled = false;
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res._status, 403);
});

test('unreachable + failOpen=false (default): fails closed with 503', async () => {
    global.fetch = async () => { throw new Error('ECONNREFUSED'); };
    const mw = cbBoltOn({ edgeKey: 'test-key' });
    const { req, res } = mockReqRes();
    let nextCalled = false;
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res._status, 503);
});

test('unreachable + failOpen=true: calls next() anyway', async () => {
    global.fetch = async () => { throw new Error('ECONNREFUSED'); };
    const mw = cbBoltOn({ edgeKey: 'test-key', failOpen: true });
    const { req, res } = mockReqRes();
    let nextCalled = false;
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(res._status, null);
});

test('missing edgeKey throws at construction time, not at request time', () => {
    assert.throws(() => cbBoltOn({}), /edgeKey is required/);
});
