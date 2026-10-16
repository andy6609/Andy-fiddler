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
  check(views.length === 0, 'binary body produces no text view');
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

// --- end of sections ----------------------------------------------------------
console.log(`${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
