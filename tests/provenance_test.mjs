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

// --- multipart and form ------------------------------------------------------------
{
  const docx = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(300, 0), Buffer.from('WSCANARY-docx-5')]);
  const b = 'XyZ123';
  const body = Buffer.concat([
    Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nassistants upload\r\n`),
    Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="file"; filename="report.docx"\r\nContent-Type: application/octet-stream\r\n\r\n`), docx,
    Buffer.from(`\r\n--${b}--\r\n`),
  ]);
  const { views } = await P.archiveViews({ flows: [flow(50, { req: body, reqHeaders: [['Content-Type', `multipart/form-data; boundary=${b}`]] })] });
  const filePart = views.find((v) => v.locator === 'part[1] name="file" filename="report.docx"');
  check(filePart && filePart.binary && filePart.text === P.latin1(new Uint8Array(docx)), 'multipart file part keeps the exact bytes and its form field name');
  check(views.some((v) => v.locator === 'part[0] name="purpose"' && v.text === 'assistants upload'), 'text parts become text views');
  check(views[0].locator === 'body', 'the whole body view stays first');
}
{
  const { views } = await P.archiveViews({ flows: [flow(51, { req: 'note=hello%20world%0Aline2&x=1', reqHeaders: [['Content-Type', 'application/x-www-form-urlencoded']] })] });
  check(views.some((v) => v.locator === 'form.note' && v.text === 'hello world\nline2' && v.transforms.join() === 'form'), 'urlencoded fields are percent-decoded');
}

// --- search ------------------------------------------------------------------------
{
  const fileText = 'line A\nsecret = "WSCANARY-env-1"\n';
  const flows = [
    flow(60, { req: JSON.stringify({ messages: [{ role: 'user', content: fileText }] }) }),
    flow(61, { req: 'plain text mentioning wscanary-env-1 in lower case' }),
    flow(62, { req: Buffer.concat([Buffer.from([0, 0, 1]), Buffer.from('한글 WSCANARY-env-1'), Buffer.from([0, 0, 0, 0, 0])]) }),
  ];
  const { views } = await P.archiveViews({ flows });
  const { hits } = P.search(views, 'WSCANARY-env-1');
  check(hits.some((h) => h.flowId === 60 && h.locator === '$.messages[0].content'), 'hit inside a JSON string reports its path');
  check(!hits.some((h) => h.flowId === 60 && h.locator === 'body'), 'raw-body duplicate is dropped when a decoded view matched');
  check(hits.some((h) => h.flowId === 61 && h.locator === 'body'), 'case-insensitive by default');
  check(!P.search(views, 'WSCANARY-env-1', { caseSensitive: true }).hits.some((h) => h.flowId === 61), 'case-sensitive on request');
  const binHit = P.search(views, '한글 WSCANARY').hits.find((h) => h.flowId === 62);
  check(binHit && binHit.binary && binHit.excerpt.hex, 'non-ASCII query matches inside a binary view as UTF-8 bytes');
  const one = hits.find((h) => h.flowId === 60);
  check(one.excerpt.match === 'WSCANARY-env-1' && one.excerpt.before.endsWith('secret = "'), 'excerpt shows the match with context');
  check(P.search(views, '').hits.length === 0, 'empty query finds nothing');
  const many = await P.archiveViews({ flows: [flow(63, { req: 'x '.repeat(100) })] });
  const capped = P.search(many.views, 'x', { perView: 5 });
  check(capped.hits.length === 5 && capped.truncated, 'hit count is capped per view and the cap is reported');
}

// --- canaries ----------------------------------------------------------------------
{
  const files = P.prepareFiles([
    { id: 1, name: '.env', base64: b64('# local only\nAPI_KEY=WSCANARY-env-a1\n') },
    { id: 2, name: 'src/config.ts', base64: b64('export const A = 1;\n// WSCANARY-config-b2\n') },
    { id: 3, name: 'logo.png', base64: Buffer.concat([Buffer.from([0x89, 0x50, 0, 0, 0, 1]), Buffer.from('WSCANARY-png-c3'), Buffer.alloc(40, 0)]).toString('base64') },
  ]);
  check(files[2].binary && !files[0].binary, 'binary files are recognised');
  const flows = [
    flow(70, { req: JSON.stringify({ messages: [{ role: 'user', content: 'export const A = 1;\n// WSCANARY-config-b2\n' }] }) }),
    flow(71, { req: 'telemetry WSCANARY-stray-zz' }),
    flow(72, { req: JSON.stringify({ image: Buffer.concat([Buffer.from([0x89, 0x50, 0, 0, 0, 1]), Buffer.from('WSCANARY-png-c3'), Buffer.alloc(40, 0)]).toString('base64') }) }),
  ];
  const { views } = await P.archiveViews({ flows });
  const r = P.findCanaries(files, views);
  const cfg = r.sightings.filter((x) => x.token === 'WSCANARY-config-b2');
  check(cfg.length === 1 && cfg[0].flowId === 70 && cfg[0].locator === '$.messages[0].content', 'canary found once, in its JSON string, raw duplicate collapsed');
  check(cfg[0].from[0].fileName === 'src/config.ts' && cfg[0].from[0].line === 2, 'canary is traced back to file and line');
  check(r.sightings.some((x) => x.token === 'WSCANARY-png-c3' && x.flowId === 72 && x.transforms.includes('base64')), 'canary inside a base64 image is found');
  check(r.notSeen.length === 1 && r.notSeen[0].token === 'WSCANARY-env-a1', 'files whose canary never appeared are listed');
  check(r.unknown.length === 1 && r.unknown[0] === 'WSCANARY-stray-zz', 'tokens seen in traffic but in no registered file are listed');
}

// --- end of sections ----------------------------------------------------------
console.log(`${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
