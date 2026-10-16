// Tests for web/provenance.js, run with node (no browser, no engine).
//   node tests/provenance_test.mjs
import { createRequire } from 'node:module';
import { gzipSync, deflateSync } from 'node:zlib';

const require = createRequire(import.meta.url);
const P = require('../web/provenance.js');

let checks = 0, failures = 0;
function check(cond, label) {
  checks++;
  if (!cond) { failures++; console.error(`FAIL ${label}`); }
}

const b64 = (s) => Buffer.from(s).toString('base64');
// A flow shaped like Flow::detail() in an archive.
function flow(id, { req = '', res = '', reqHeaders = [], resHeaders = [], truncated = false } = {}) {
  const body = (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return { base64: buf.toString('base64'), captured: buf.length, total: truncated ? buf.length + 100 : buf.length, truncated };
  };
  return { id, method: 'POST', host: 'api.test', path: '/x', request: { headers: reqHeaders, body: body(req) }, response: { headers: resHeaders, body: body(res) } };
}

// --- raw view ---------------------------------------------------------------
{
  const { views, notes } = await P.archiveViews({ flows: [flow(1, { req: 'hello request', res: 'hello response' })] });
  check(views.length === 2, 'one raw view per non-empty side');
  check(views[0].locator === 'body' && views[0].transforms.length === 0 && views[0].text === 'hello request', 'raw view keeps the text and has no transforms');
  check(notes.length === 0, 'no notes for complete bodies');
}
{
  const { views } = await P.archiveViews({ flows: [flow(2, { req: Buffer.from([0, 1, 2, 3, 0, 0, 255, 254]) })] });
  check(views.length === 1 && views[0].binary, 'binary body produces a binary view, not a text view');
}
{
  const { notes } = await P.archiveViews({ flows: [flow(3, { req: 'cut', truncated: true })] });
  check(notes.length === 1 && /only the first 3 of 103 bytes/.test(notes[0].note), 'truncated body is reported, not hidden');
}
{
  const { views, notes } = await P.archiveViews({ flows: [{ id: 4, request: { headers: [], body: { base64: '', redacted: true, total: 10 } }, response: { headers: [], body: {} } }] });
  check(views.length === 0 && notes[0].note.includes('redacted'), 'redacted body is reported');
}

// --- content-encoding ---------------------------------------------------------
{
  const text = 'line one\nline two WSCANARY-gz-1\n';
  const { views } = await P.archiveViews({ flows: [
    flow(10, { res: gzipSync(text), resHeaders: [['Content-Encoding', 'gzip']] }),
    flow(11, { res: deflateSync(text), resHeaders: [['content-encoding', 'deflate']] }),
  ] });
  check(views.length === 2 && views.every((v) => v.text === text), 'gzip and deflate bodies are decoded');
  check(views[0].transforms.join() === 'gzip' && views[1].transforms.join() === 'deflate', 'decoding is recorded as a transform');
}
{
  const whole = gzipSync('A'.repeat(5000) + 'tail');
  const { views, notes } = await P.archiveViews({ flows: [flow(12, { res: whole.subarray(0, whole.length - 8), resHeaders: [['Content-Encoding', 'gzip']], truncated: true })] });
  check(views.length === 1 && views[0].text.startsWith('AAAA'), 'a cut gzip stream still yields the decoded prefix');
  check(notes.some((n) => /gzip decoding stopped/.test(n.note)), 'the decoder error is reported');
}
{
  const { views, notes } = await P.archiveViews({ flows: [flow(13, { res: 'not really brotli', resHeaders: [['Content-Encoding', 'br']] })] });
  check(views.length === 1 && views[0].transforms.length === 0, 'unsupported encodings fall back to the bytes as captured');
  check(notes.some((n) => /br is not decoded/.test(n.note)), 'unsupported encoding is reported');
}

// --- JSON string values --------------------------------------------------------
{
  const fileText = 'const KEY = "WSCANARY-cfg-9";\nexport default KEY;\n';
  const body = JSON.stringify({ model: 'm', messages: [{ role: 'user', content: [{ type: 'tool_result', content: fileText }] }], 'odd.key': 'value here' });
  const { views } = await P.archiveViews({ flows: [flow(20, { req: body })] });
  const v = views.find((x) => x.locator === '$.messages[0].content[0].content');
  check(v && v.text === fileText, 'escaped file text comes back unescaped inside its JSON string view');
  check(v && v.transforms.join() === 'json', 'JSON extraction is recorded as a transform');
  check(views.some((x) => x.locator === '$["odd.key"]'), 'keys that are not identifiers are bracketed in the path');
  check(!views.some((x) => x.text === 'm'), 'very short strings are skipped');
  check(views[0].text.includes('\\n'), 'the raw view still shows the escaped form');
}
{
  const { views } = await P.archiveViews({ flows: [flow(21, { req: '{"a": "unterminated', res: '' })] });
  check(views.length === 1 && views[0].locator === 'body', 'invalid JSON keeps only the raw view');
}

// --- server-sent events ----------------------------------------------------------
{
  const pieces = ['int main(', 'int argc) {\n', '  return run();\n', '}\n'];
  const sse = pieces.map((t, i) => `event: content_block_delta\ndata: ${JSON.stringify({ index: 0, delta: { type: 'text_delta', text: t } })}\n\n`).join('') + 'event: ping\ndata: keepalive\n\n';
  const { views } = await P.archiveViews({ flows: [flow(30, { res: sse, resHeaders: [['Content-Type', 'text/event-stream']] })] });
  const joined = views.find((v) => v.locator === 'events[*].delta.text (joined 4)');
  check(joined && joined.text === pieces.join(''), 'streamed text pieces are joined in event order');
  check(joined && joined.transforms.join() === 'sse,json,join', 'joining is recorded as a transform');
  check(views.some((v) => v.locator === 'events[1].delta.text' && v.text === 'int argc) {\n'), 'each event field is also its own view');
  check(views.some((v) => v.locator === 'events[4].data' && v.text === 'keepalive'), 'non-JSON event data is kept as text');
  check(views.some((v) => v.locator === 'events[*].delta.type (joined 4)' && v.text === 'text_delta'.repeat(4)), 'every repeated field gets a joined view, not only text');
}

// --- base64 and binary --------------------------------------------------------
{
  const doc = '# Notes\nWSCANARY-notes-3 lives here.\n'.repeat(4);
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 13]), Buffer.alloc(80, 7)]);
  const body = JSON.stringify({ attachments: [{ name: 'notes.md', data: Buffer.from(doc).toString('base64') }, { image: `data:image/png;base64,${png.toString('base64')}` }], note: 'plain words that are not base64 at all, even if long enough to be considered' });
  const { views } = await P.archiveViews({ flows: [flow(40, { req: body })] });
  const text = views.find((v) => v.locator === '$.attachments[0].data' && v.transforms.join() === 'json,base64');
  check(text && text.text === doc && !text.binary, 'base64 text inside JSON is decoded to a text view');
  const bin = views.find((v) => v.locator === '$.attachments[1].image' && v.binary);
  check(bin && bin.text === P.latin1(new Uint8Array(png)), 'data: URL images become binary views with the exact bytes');
  check(!views.some((v) => v.locator === '$.note' && v.transforms.includes('base64')), 'ordinary long text is not mistaken for base64');
}
{
  const raw = Buffer.from([1, 2, 3, 0, 0, 0, 200, 201, 202, 0, 5]);
  const { views } = await P.archiveViews({ flows: [flow(41, { req: raw })] });
  check(views.length === 1 && views[0].binary && views[0].text.length === raw.length, 'binary bodies become one binary view');
}

// --- end of sections ----------------------------------------------------------
console.log(`${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
