// Tests for web/provenance.js, run with node (no browser, no engine).
//   node tests/provenance_test.mjs
import { createRequire } from 'node:module';
import zlib, { gzipSync, deflateSync } from 'node:zlib';
import crypto from 'node:crypto';

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

// --- line helpers ---------------------------------------------------------------------
{
  const arrow = P.splitLines('     1→#include <cstdio>\n     2→int main() {\n     3→  return 0;\n     4→}');
  check(arrow.stripped && arrow.lines[1] === 'int main() {', 'arrow-numbered tool output is unnumbered');
  const tab = P.splitLines('1\tfirst line\n2\tsecond line\n\n3\tthird line');
  check(tab.stripped && tab.lines[3] === 'third line', 'tab-numbered lines are unnumbered, blank lines kept in place');
  const plain = P.splitLines('2024 was a year\nnothing numbered here\nreally');
  check(!plain.stripped, 'text that only occasionally starts with digits is left alone');
  check(P.isTrivial('});') && P.isTrivial('return') && !P.isTrivial('const apiBase = process.env.API_BASE;'), 'short or punctuation-only lines are trivial');
}

// --- line runs and coverage -------------------------------------------------------
{
  const source = [
    '#include "net.hpp"',                      // 1
    '#include "packet.hpp"',                   // 2
    '',                                         // 3
    'int main(int argc, char** argv) {',       // 4
    '    auto options = parseOptions(argc, argv);', // 5
    '    if (!options.valid) return usage();',  // 6
    '    return runEngine(options);',           // 7
    '}',                                        // 8
    '',                                         // 9
    'static int usage() {',                     // 10
    '    std::puts("usage: wirescope [--port N]");', // 11
    '    return 2;',                            // 12
    '}',                                        // 13
  ].join('\n');
  const [file] = P.prepareFiles([{ id: 9, name: 'src/main.cpp', base64: b64(source) }]);
  const view = (id, text, transforms = ['json']) => ({ flowId: id, side: 'request', locator: '$.content', transforms, text, binary: false });

  // 1) the agent read lines 4-8 through a numbering tool
  const partial = source.split('\n').slice(3, 8).map((l, k) => `${String(k + 4).padStart(6)}→${l}`).join('\n');
  const r1 = P.lineRuns(file, view(80, `Here is the file:\n${partial}\nWhat next?`));
  check(r1.length === 1 && r1[0].fileFrom === 4 && r1[0].fileTo === 8, 'partial read matches exactly the lines that were sent');
  check(r1[0].transforms.join() === 'json,line-numbers', 'line-number stripping is recorded');

  // 2) re-indented copy still matches (whitespace-insensitive per line)
  const r2 = P.lineRuns(file, view(81, source.split('\n').slice(9, 13).map((l) => '  ' + l.trim()).join('\r\n')));
  check(r2.length === 1 && r2[0].fileFrom === 10 && r2[0].fileTo === 13, 're-indented CRLF copy still matches');

  // 3) a single trivial line is not evidence
  check(P.lineRuns(file, view(82, 'return 2;\n}\n')).length === 0, 'a lone trivial line does not count as a match');

  // 4) one long distinctive line is enough on its own
  const r4 = P.lineRuns(file, view(83, 'see:    std::puts("usage: wirescope [--port N]");'.replace('see:', '')));
  check(r4.length === 1 && r4[0].fileFrom === 11, 'one long distinctive line counts');

  // 5) the end cut off by the capture limit: the cut line is not claimed
  const cut = source.slice(0, source.indexOf('return runEngine') + 10);
  const r5 = P.lineRuns(file, view(84, cut));
  check(r5.length === 1 && r5[0].fileFrom === 1 && r5[0].fileTo === 6, 'a truncated tail only claims whole lines');

  const cov = P.coverage(file, [...r1, ...r5]);
  check(cov.anchorLines === 9 && cov.matchedAnchors === 6, `coverage counts non-trivial lines only (${cov.matchedAnchors}/${cov.anchorLines})`);
  check(JSON.stringify(cov.ranges) === '[[1,8]]', 'covered ranges are merged');
}

// --- binary files ---------------------------------------------------------------------
{
  const blob = Buffer.alloc(20000);
  for (let i = 0; i < blob.length; i++) blob[i] = (i * 31 + 7) & 0xff;
  const [file] = P.prepareFiles([{ id: 5, name: 'diagram.png', base64: blob.toString('base64') }]);
  const bview = (id, bytes) => ({ flowId: id, side: 'request', locator: 'part[0] name="file"', transforms: ['multipart'], text: P.latin1(new Uint8Array(bytes)), binary: true });
  const whole = P.byteRuns(file, bview(90, Buffer.concat([Buffer.from('xx'), blob, Buffer.from('yy')])));
  check(whole.length === 1 && whole[0].whole && whole[0].viewOffset === 2, 'whole binary file found with its offset');
  const cut = P.byteRuns(file, bview(91, blob.subarray(0, 9000)));
  check(cut.length === 1 && !cut[0].whole && cut[0].bytes === 8192, 'cut upload: longest 4 KiB-step prefix is reported');
  check(P.byteRuns(file, bview(92, Buffer.alloc(30000, 1))).length === 0, 'unrelated bytes do not match');
}

// --- analyze(): one archive end to end ------------------------------------------------
{
  const config = 'export const apiBase = "https://api.internal.test";\nexport const retries = 3; // WSCANARY-cfg-q9\nexport const timeoutMs = 15000;\n';
  const readme = '# Sandbox\nThis repository exists only for the egress experiment.\nNothing here is real.\n';
  const archive = {
    bodyLimit: 1048576,
    localFiles: [
      { id: 1, name: 'src/config.ts', base64: b64(config) },
      { id: 2, name: 'README.md', base64: b64(readme) },
    ],
    flows: [
      flow(100, { req: JSON.stringify({ messages: [{ role: 'user', content: [{ type: 'tool_result', content: config.split('\n').map((l, i) => `${String(i + 1).padStart(6)}→${l}`).join('\n') }] }] }) }),
      flow(101, { req: `plain upload of the readme:\n${readme}`, reqHeaders: [['Content-Type', 'text/plain']] }),
      flow(102, { res: gzipSync(JSON.stringify({ summary: 'export const retries = 3; // WSCANARY-cfg-q9' })), resHeaders: [['Content-Encoding', 'gzip']] }),
    ],
  };
  const r = await P.analyze(archive);
  const cfgMatch = r.matches.find((m) => m.fileName === 'src/config.ts' && m.flowId === 100);
  check(cfgMatch && cfgMatch.fileFrom === 1 && cfgMatch.fileTo === 3 && cfgMatch.locator === '$.messages[0].content[0].content', 'config lines traced to the tool_result string');
  check(cfgMatch && cfgMatch.transforms.join() === 'json,line-numbers', 'transforms explain how it matched');
  check(r.matches.some((m) => m.fileName === 'README.md' && m.flowId === 101 && m.locator === 'body'), 'plain-text body matches in the raw view');
  check(!r.matches.some((m) => m.flowId === 100 && m.locator === 'body'), 'no duplicate match from the escaped raw body');
  check(r.canaries.sightings.filter((x) => x.token === 'WSCANARY-cfg-q9').map((x) => x.flowId).join() === '100,102', 'canary seen in the request and echoed in a gzip response');
  check(r.coverage.find((c) => c.fileName === 'src/config.ts').ratio === 1, 'whole config covered');
  check(r.files.length === 2 && r.bodyLimit === 1048576 && r.viewCount > 3, 'summary fields present');
}

// --- one match per body and range ------------------------------------------------------
{
  const notes = 'Release notes for the sandbox repository go here.\nEach entry describes one observed behaviour change.\n';
  const sse = ['Echo: ', 'Release notes for the sandbox repository go here.\n', 'Each entry describes one observed behaviour change.\n']
    .map((t) => `data: ${JSON.stringify({ delta: { text: t } })}\n\n`).join('');
  const r = await P.analyze({ localFiles: [{ id: 1, name: 'NOTES.md', base64: b64(notes) }], flows: [flow(110, { res: sse, resHeaders: [['Content-Type', 'text/event-stream']] })] });
  const hits = r.matches.filter((m) => m.flowId === 110);
  check(hits.length === 2 && hits.every((m) => !m.transforms.includes('join')), 'a range seen in an event and in the joined stream is reported once, at the event');
}

// --- long lines quoted inside other text ---------------------------------------------------
{
  const readme = '# Sandbox repo\nThis repository exists only for the egress experiment.\nshort line\n';
  const r = await P.analyze({ localFiles: [{ id: 1, name: 'README.md', base64: b64(readme) }],
    flows: [flow(120, { res: JSON.stringify({ answer: 'The README says: This repository exists only for the egress experiment. That is all.' }) })] });
  const f = r.matches.find((m) => m.kind === 'fragment');
  check(f && f.fileFrom === 2 && f.locator === '$.answer', 'a long file line quoted inside a sentence is a fragment match');
  check(r.coverage[0].matchedAnchors === 1, 'fragments count toward coverage');
  const none = await P.analyze({ localFiles: [{ id: 1, name: 'README.md', base64: b64(readme) }], flows: [flow(121, { res: JSON.stringify({ answer: 'it has a short line in it' }) })] });
  check(!none.matches.length, 'short lines are never matched as fragments');
}

// --- raw DEFLATE (for WebSocket permessage-deflate) ------------------------------
// Compress one message at a time on a shared stream with a sync flush, the way permessage-deflate does,
// and drop the 00 00 ff ff tail the sender removes.
function messageDeflater(options = {}) {
  const z = zlib.createDeflateRaw(options);
  return (data) => new Promise((resolve) => {
    const chunks = [];
    const on = (c) => chunks.push(c);
    z.on('data', on);
    z.write(data);
    z.flush(zlib.constants.Z_SYNC_FLUSH, () => { z.off('data', on); const all = Buffer.concat(chunks); resolve(all.subarray(0, all.length - 4)); });
  });
}
const withTail = (payload) => new Uint8Array(Buffer.concat([payload, Buffer.from([0, 0, 0xff, 0xff])]));
{
  const text = Buffer.from(Array.from({ length: 3000 }, (_, i) => `line ${i} of a repetitive body ${(i * 7919) % 1000}`).join('\n'));
  const same = (input, want) => { const r = P.inflateRaw(new Uint8Array(input)); return !r.error && Buffer.from(r.bytes).equals(want); };
  check(same(zlib.deflateRawSync(text, { level: 0 }), text), 'inflateRaw: stored blocks');
  check(same(zlib.deflateRawSync(Buffer.from('hello hello hello'), { strategy: zlib.constants.Z_FIXED }), Buffer.from('hello hello hello')), 'inflateRaw: fixed Huffman block');
  check(same(zlib.deflateRawSync(text, { level: 9 }), text), 'inflateRaw: dynamic Huffman blocks');
  const random = crypto.randomBytes(50000);
  check(same(zlib.deflateRawSync(random), random), 'inflateRaw: incompressible bytes');
  const cut = P.inflateRaw(new Uint8Array(zlib.deflateRawSync(text).subarray(0, 300)));
  check(cut.error === 'compressed data ended early' && cut.bytes.length > 0, 'inflateRaw: a cut stream returns what decoded and says why it stopped');
  check(P.inflateRaw(new Uint8Array([0xff, 0xff])).error !== '', 'inflateRaw: garbage is an error, not an exception');

  const deflate = messageDeflater();
  const first = 'first message: export const timeoutMs = 15000;';
  const second = 'second message repeats: export const timeoutMs = 15000; and more';
  const p1 = await deflate(first), p2 = await deflate(second);
  const r1 = P.inflateRaw(withTail(p1));
  const r2 = P.inflateRaw(withTail(p2), r1.history);
  check(Buffer.from(r1.bytes).toString() === first && Buffer.from(r2.bytes).toString() === second, 'inflateRaw: messages decode in order with the window carried over');
  check(p2.length < Buffer.byteLength(second) && P.inflateRaw(withTail(p2)).error !== '', 'inflateRaw: the second message really points into the first (fails without the window)');
}

// --- end of sections ----------------------------------------------------------
console.log(`${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
