// WireScope provenance: which part of which local file showed up in which request.
//
// Pure functions, no DOM. The same file runs in three places:
//   - the live inspector (loaded next to app.js),
//   - offline HTML reports (inlined before app.js),
//   - node (scripts and tests) through module.exports.
//
// Vocabulary
//   view    one readable rendering of a body: the raw text, the text after gzip, one JSON string value,
//           one SSE event field, one multipart part ... Every view remembers how it was obtained
//           (`transforms`) and where it sits (`locator`), so a match can always say how it matched.
//   match   a run of local-file lines, or a canary token, found inside a view.
//
// What a match proves: these bytes were inside this request or response as captured by the proxy.
// What it does not prove: which process read the file, or that the whole file was sent.
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.WireScopeProvenance = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Bytes and text
  // ---------------------------------------------------------------------------

  function b64ToBytes(b64) {
    const bin = atob(b64 || '');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const utf8 = new TextDecoder('utf-8');
  const decodeText = (bytes) => utf8.decode(bytes);

  // Same heuristic as the inspector: few control characters and valid UTF-8 in the first 4 KiB.
  function isMostlyText(bytes) {
    const n = Math.min(bytes.length, 4096);
    if (!n) return true;
    let control = 0;
    for (let i = 0; i < n; i++) {
      const c = bytes[i];
      if (c < 9 || (c > 13 && c < 32) || c === 127) control++;
    }
    if (control > n * 0.02) return false;
    try { new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, n), { stream: true }); return true; } catch { return false; }
  }

  function headerValue(headers, name) {
    name = name.toLowerCase();
    for (const [k, v] of headers || []) if (String(k).toLowerCase() === name) return String(v);
    return '';
  }

  // Content-Encoding: gzip/deflate through DecompressionStream (browsers and node 18+).
  // A truncated body still yields what decoded before the stream ended; the error is returned too.
  const DECODERS = { gzip: 'gzip', 'x-gzip': 'gzip', deflate: 'deflate' };
  async function decompress(bytes, encoding) {
    const ds = new DecompressionStream(DECODERS[encoding]);
    const writer = ds.writable.getWriter();
    writer.write(bytes).catch(() => {});
    writer.close().catch(() => {});
    const reader = ds.readable.getReader();
    const parts = [];
    let total = 0, error = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
        total += value.length;
      }
    } catch (e) { error = e.message || String(e); }
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return { bytes: out, error };
  }

  // ---------------------------------------------------------------------------
  // Views of one body
  // ---------------------------------------------------------------------------

  // A view is { flowId, side, locator, transforms, text }. `notes` collects what could not be looked at.
  function makeView(flow, side, locator, transforms, text) {
    return { flowId: flow.id, side, locator, transforms, text };
  }

  async function bodyViews(flow, side, notes = []) {
    const msg = flow[side] || {};
    const body = msg.body || {};
    if (body.redacted) { notes.push({ flowId: flow.id, side, note: 'body removed in redacted export' }); return []; }
    const bytes = b64ToBytes(body.base64);
    if (!bytes.length) return [];
    if (body.truncated) notes.push({ flowId: flow.id, side, note: `only the first ${body.captured} of ${body.total} bytes were captured` });
    // Undo Content-Encoding first; everything below works on the decoded bytes.
    let base = bytes;
    const transforms = [];
    const encoding = headerValue(msg.headers, 'content-encoding').toLowerCase().trim();
    if (encoding && encoding !== 'identity') {
      if (DECODERS[encoding] && typeof DecompressionStream !== 'undefined') {
        const d = await decompress(bytes, encoding);
        if (d.error) notes.push({ flowId: flow.id, side, note: `${encoding} decoding stopped after ${d.bytes.length} bytes: ${d.error}` });
        base = d.bytes;
        transforms.push(encoding.replace('x-', ''));
      } else {
        notes.push({ flowId: flow.id, side, note: `content-encoding ${encoding} is not decoded; searched the encoded bytes` });
      }
    }
    const views = [];
    if (isMostlyText(base)) views.push(makeView(flow, side, 'body', transforms, decodeText(base)));
    return views;
  }

  async function archiveViews(archive) {
    const notes = [];
    const views = [];
    for (const flow of archive.flows || []) {
      for (const side of ['request', 'response']) views.push(...await bodyViews(flow, side, notes));
    }
    return { views, notes };
  }

  return { b64ToBytes, decodeText, isMostlyText, headerValue, decompress, bodyViews, archiveViews };
});
