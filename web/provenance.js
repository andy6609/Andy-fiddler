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

  // multipart/form-data: the classic upload form (claude.ai used plain multipart in the internship captures).
  // Split on the boundary at the byte level, then each part becomes a view named after its form field.
  function multipartViews(flow, side, transforms, bytes, contentType) {
    const m = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
    if (!m) return [];
    const boundary = `--${m[1] || m[2]}`;
    const all = latin1(bytes);
    const views = [];
    let pos = all.indexOf(boundary);
    let index = 0;
    while (pos >= 0) {
      const start = pos + boundary.length;
      if (all.startsWith('--', start)) break;                    // closing boundary
      const next = all.indexOf(`\r\n${boundary}`, start);
      const end = next < 0 ? all.length : next;                  // last part may be cut by the capture limit
      const part = all.slice(start, end).replace(/^\r\n/, '');
      const split = part.indexOf('\r\n\r\n');
      if (split >= 0) {
        const head = part.slice(0, split);
        const disposition = /content-disposition:[^\r\n]*/i.exec(head);
        const name = disposition && /\bname="([^"]*)"/i.exec(disposition[0]);
        const file = disposition && /filename="([^"]*)"/i.exec(disposition[0]);
        const locator = `part[${index}]${name ? ` name="${name[1]}"` : ''}${file ? ` filename="${file[1]}"` : ''}`;
        const content = part.slice(split + 4);
        const contentBytes = new Uint8Array(content.length);
        for (let i = 0; i < content.length; i++) contentBytes[i] = content.charCodeAt(i);
        views.push(bytesView(flow, side, locator, [...transforms, 'multipart'], contentBytes));
      }
      index++;
      if (next < 0) break;
      pos = next + 2;
    }
    return views;
  }

  // application/x-www-form-urlencoded: one view per field, percent-decoded.
  function formViews(flow, side, transforms, text) {
    const views = [];
    for (const [k, v] of new URLSearchParams(text)) if (v.length >= MIN_STRING) views.push(makeView(flow, side, `form.${k}`, [...transforms, 'form'], v));
    return views;
  }

  // A view is { flowId, side, locator, transforms, text, binary }. `notes` collects what could not be looked at.
  // Binary views carry the bytes as a latin1 string (one char per byte) so exact byte runs can be found with indexOf.
  function makeView(flow, side, locator, transforms, text, binary = false) {
    return { flowId: flow.id, side, locator, transforms, text, binary };
  }
  const latin1 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)); return s; };
  function bytesView(flow, side, locator, transforms, bytes) {
    return isMostlyText(bytes) ? makeView(flow, side, locator, transforms, decodeText(bytes)) : makeView(flow, side, locator, transforms, latin1(bytes), true);
  }

  // Attachments often ride inside JSON as base64 (images, documents, "file_data" fields).
  // Only long strings made purely of the base64 alphabet are tried, so ordinary text is left alone.
  const BASE64_MIN = 64;
  function base64Views(flow, side, transforms, strings) {
    const out = [];
    for (const [path, value] of strings) {
      const v = value.startsWith('data:') && value.includes(';base64,') ? value.slice(value.indexOf(';base64,') + 8) : value;
      if (v.length < BASE64_MIN || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) continue;
      let bytes;
      try { bytes = b64ToBytes(v); } catch { continue; }
      out.push(bytesView(flow, side, path, [...transforms, 'json', 'base64'], bytes));
    }
    return out;
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
    const contentType = headerValue(msg.headers, 'content-type');
    if (/multipart\/form-data/i.test(contentType)) views.push(...multipartViews(flow, side, transforms, base, contentType));
    if (!isMostlyText(base)) { views.unshift(makeView(flow, side, 'body', transforms, latin1(base), true)); return views; }
    const text = decodeText(base);
    if (/x-www-form-urlencoded/i.test(contentType)) views.push(...formViews(flow, side, transforms, text));
    views.unshift(makeView(flow, side, 'body', transforms, text));
    const parsed = tryJson(text);
    if (parsed.ok) {
      const strings = jsonStrings(parsed.value, '$', []);
      for (const [path, value] of strings) views.push(makeView(flow, side, path, [...transforms, 'json'], value));
      views.push(...base64Views(flow, side, transforms, strings));
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

  // ---------------------------------------------------------------------------
  // Search across every view
  // ---------------------------------------------------------------------------

  // Plain substring search. The same text is usually visible twice (escaped in the raw body, unescaped in its
  // JSON string), so raw-body hits are dropped for a body when a decoded view of that body also matched.
  function search(views, query, { caseSensitive = false, perView = 20, limit = 2000 } = {}) {
    if (!query) return { hits: [], truncated: false };
    const needle = caseSensitive ? query : query.toLowerCase();
    const needleBytes = latin1(new TextEncoder().encode(query));   // how the query looks inside binary views
    const hits = [];
    let truncated = false;
    for (const v of views) {
      const hay = v.binary ? v.text : caseSensitive ? v.text : v.text.toLowerCase();
      const n = v.binary ? needleBytes : needle;
      let from = 0, count = 0;
      for (;;) {
        const at = hay.indexOf(n, from);
        if (at < 0) break;
        if (count++ >= perView) { truncated = true; break; }
        hits.push({ flowId: v.flowId, side: v.side, locator: v.locator, transforms: v.transforms, binary: v.binary, offset: at, length: n.length, excerpt: excerpt(v, at, n.length) });
        from = at + Math.max(1, n.length);
      }
      if (hits.length >= limit) { truncated = true; break; }
    }
    const derived = new Set(hits.filter((h) => h.locator !== 'body').map((h) => `${h.flowId}/${h.side}`));
    return { hits: hits.filter((h) => h.locator !== 'body' || !derived.has(`${h.flowId}/${h.side}`)), truncated };
  }

  // Up to 60 characters of context on each side; binary views show bytes as hex around the match.
  function excerpt(view, at, length) {
    if (view.binary) {
      const hex = (str) => Array.from(str, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
      return { before: hex(view.text.slice(Math.max(0, at - 8), at)), match: hex(view.text.slice(at, at + Math.min(length, 32))), after: hex(view.text.slice(at + length, at + length + 8)), hex: true };
    }
    return { before: view.text.slice(Math.max(0, at - 60), at), match: view.text.slice(at, at + length), after: view.text.slice(at + length, at + length + 60), hex: false };
  }

  // ---------------------------------------------------------------------------
  // Local files and canaries
  // ---------------------------------------------------------------------------

  // archive.localFiles entries -> { id, name, bytes, binary, text }. Binary files keep latin1 text for byte search.
  function prepareFiles(localFiles) {
    return (localFiles || []).map((f) => {
      const bytes = b64ToBytes(f.base64);
      const binary = !isMostlyText(bytes);
      return { id: f.id, name: f.name, size: bytes.length, bytes, binary, text: binary ? latin1(bytes) : decodeText(bytes) };
    });
  }

  // A canary is a random marker planted in an experiment file. Unlike ordinary text it can only have come
  // from that file, so finding it in a request is unambiguous evidence of where those bytes went.
  const CANARY = /WSCANARY-[A-Za-z0-9_-]{2,64}/g;
  const lineAt = (text, offset) => { let n = 1; for (let i = text.indexOf('\n'); i >= 0 && i < offset; i = text.indexOf('\n', i + 1)) n++; return n; };

  function findCanaries(files, views, pattern = CANARY) {
    const origin = new Map();                 // token -> [{fileId, fileName, line}]
    for (const f of files) {
      for (const m of f.text.matchAll(new RegExp(pattern.source, 'g'))) {
        if (!origin.has(m[0])) origin.set(m[0], []);
        origin.get(m[0]).push({ fileId: f.id, fileName: f.name, line: f.binary ? null : lineAt(f.text, m.index) });
      }
    }
    const sightings = [];
    const seen = new Set();
    for (const v of views) {
      for (const m of v.text.matchAll(new RegExp(pattern.source, 'g'))) {
        // a token cut off by the capture limit is still a prefix of the real one; report what was captured
        const token = m[0];
        sightings.push({ token, flowId: v.flowId, side: v.side, locator: v.locator, transforms: v.transforms, offset: m.index, from: origin.get(token) || [] });
        seen.add(token);
      }
    }
    // collapse the same token found in the raw body and in a decoded view of the same body
    const derived = new Set(sightings.filter((x) => x.locator !== 'body').map((x) => `${x.token}/${x.flowId}/${x.side}`));
    const unique = sightings.filter((x) => x.locator !== 'body' || !derived.has(`${x.token}/${x.flowId}/${x.side}`));
    const notSeen = [...origin].filter(([token]) => !seen.has(token)).map(([token, from]) => ({ token, from }));
    const unknown = [...new Set(unique.filter((x) => !x.from.length).map((x) => x.token))];
    return { sightings: unique, notSeen, unknown };
  }

  return { prepareFiles, findCanaries, search, b64ToBytes, decodeText, isMostlyText, headerValue, decompress, jsonStrings, parseSse, latin1, bodyViews, archiveViews };
});
