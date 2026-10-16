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

  // JSON: each string value becomes its own view, already unescaped (\n, \", \uXXXX), with its path.
  // That is where file contents usually travel: inside a JSON string in a chat or tool-result field.
  const MIN_STRING = 4;
  const keyPath = (k) => (/^[A-Za-z_$][\w$-]*$/.test(k) ? `.${k}` : `[${JSON.stringify(k)}]`);
  function jsonStrings(value, path, out) {
    if (typeof value === 'string') { if (value.length >= MIN_STRING) out.push([path, value]); return out; }
    if (Array.isArray(value)) { value.forEach((x, i) => jsonStrings(x, `${path}[${i}]`, out)); return out; }
    if (value && typeof value === 'object') for (const k of Object.keys(value)) jsonStrings(value[k], path + keyPath(k), out);
    return out;
  }
  function tryJson(text) { try { return { ok: true, value: JSON.parse(text) }; } catch { return { ok: false }; } }

  // Server-sent events: a streamed reply arrives in many small events. Each event's data is a view, and
  // the same JSON field across events is also joined in order (e.g. every delta.text), because text a
  // model writes back is split across events and would never match piece by piece.
  function parseSse(text) {
    const events = [];
    for (const block of text.split(/\r?\n\r?\n/)) {
      if (!block.trim()) continue;
      const data = [];
      let event = 'message';
      for (const line of block.split(/\r?\n/)) {
        if (line.startsWith(':')) continue;
        const i = line.indexOf(':');
        const field = i < 0 ? line : line.slice(0, i);
        let value = i < 0 ? '' : line.slice(i + 1);
        if (value.startsWith(' ')) value = value.slice(1);
        if (field === 'data') data.push(value);
        else if (field === 'event') event = value;
      }
      events.push({ event, data: data.join('\n') });
    }
    return events;
  }
  const looksLikeSse = (contentType, text) => /event-stream/i.test(contentType) || /^(event|data|id):/m.test(text.slice(0, 200));

  function sseViews(flow, side, transforms, text) {
    const views = [];
    const joined = new Map();   // json path -> pieces in event order
    parseSse(text).forEach((ev, i) => {
      const parsed = tryJson(ev.data);
      if (!parsed.ok) {
        if (ev.data.length >= MIN_STRING) views.push(makeView(flow, side, `events[${i}].data`, [...transforms, 'sse'], ev.data));
        return;
      }
      for (const [path, value] of jsonStrings(parsed.value, '$', [])) {
        views.push(makeView(flow, side, `events[${i}]${path.slice(1)}`, [...transforms, 'sse', 'json'], value));
      }
      // short pieces are exactly what joining is for, so collect them without the length floor
      (function walk(v, path) {
        if (typeof v === 'string') { if (!joined.has(path)) joined.set(path, []); joined.get(path).push(v); }
        else if (Array.isArray(v)) v.forEach((x, k) => walk(x, `${path}[${k}]`));
        else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], path + keyPath(k));
      })(parsed.value, '$');
    });
    for (const [path, pieces] of joined) {
      if (pieces.length < 2) continue;
      views.push(makeView(flow, side, `events[*]${path.slice(1)} (joined ${pieces.length})`, [...transforms, 'sse', 'json', 'join'], pieces.join('')));
    }
    return views;
  }

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
    if (!isMostlyText(base)) return views;
    const text = decodeText(base);
    views.push(makeView(flow, side, 'body', transforms, text));
    const parsed = tryJson(text);
    if (parsed.ok) {
      for (const [path, value] of jsonStrings(parsed.value, '$', [])) views.push(makeView(flow, side, path, [...transforms, 'json'], value));
    } else if (looksLikeSse(headerValue(msg.headers, 'content-type'), text)) {
      views.push(...sseViews(flow, side, transforms, text));
    }
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

  return { b64ToBytes, decodeText, isMostlyText, headerValue, decompress, jsonStrings, parseSse, bodyViews, archiveViews };
});
