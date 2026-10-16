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
  // Raw DEFLATE (RFC 1951), for WebSocket permessage-deflate
  // ---------------------------------------------------------------------------

  // permessage-deflate (RFC 7692) keeps one LZ77 window per direction across messages by default, so message N
  // can copy bytes from message N-1. DecompressionStream cannot be fed one message at a time and asked what came out
  // for it, so this small synchronous decoder keeps the window by hand. Same algorithm as zlib's puff.c: Huffman codes
  // are decoded bit by bit, which is slow but simple, and the bodies here are kilobytes to a few megabytes.
  const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
  const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
  const WINDOW = 32768;

  // Canonical Huffman code from code lengths: how many codes of each length, and the symbols in code order.
  function huffman(lengths) {
    const count = new Uint16Array(16), offs = new Uint16Array(16), symbol = new Uint16Array(lengths.length);
    for (const l of lengths) count[l]++;
    count[0] = 0;
    for (let l = 1; l < 15; l++) offs[l + 1] = offs[l] + count[l];
    for (let s = 0; s < lengths.length; s++) if (lengths[s]) symbol[offs[lengths[s]]++] = s;
    return { count, symbol };
  }
  let fixedCodes = null;
  function fixed() {
    if (!fixedCodes) {
      const l = new Uint8Array(288);
      l.fill(8, 0, 144); l.fill(9, 144, 256); l.fill(7, 256, 280); l.fill(8, 280, 288);
      fixedCodes = { lit: huffman(l), dist: huffman(new Uint8Array(30).fill(5)) };
    }
    return fixedCodes;
  }

  // Decodes `input` with `history` (the previous output, up to 32 KiB) as the starting window.
  // Returns { bytes, history, error }: what was decoded (also when it stopped on an error) and the window to carry on.
  // The input ends either at a final block or, for permessage-deflate, right after an empty stored block (sync flush).
  function inflateRaw(input, history = new Uint8Array(0)) {
    let out = new Uint8Array(Math.max(1024, history.length + input.length * 4));
    out.set(history);
    const start = history.length;
    let o = start, pos = 0, bitbuf = 0, bitcnt = 0, error = '';
    const put = (b) => {
      if (o === out.length) { const grown = new Uint8Array(out.length * 2); grown.set(out); out = grown; }
      out[o++] = b;
    };
    const bits = (n) => {
      let v = bitbuf;
      while (bitcnt < n) {
        if (pos >= input.length) throw new Error('compressed data ended early');
        v |= input[pos++] << bitcnt;
        bitcnt += 8;
      }
      bitbuf = v >>> n;
      bitcnt -= n;
      return v & ((1 << n) - 1);
    };
    const decode = (h) => {
      let code = 0, first = 0, index = 0;
      for (let len = 1; len < 16; len++) {
        code |= bits(1);
        const count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
      }
      throw new Error('invalid Huffman code');
    };
    const codes = (lit, dist) => {
      for (;;) {
        let sym = decode(lit);
        if (sym < 256) { put(sym); continue; }
        if (sym === 256) return;
        sym -= 257;
        if (sym >= 29) throw new Error('invalid length code');
        const len = LEN_BASE[sym] + bits(LEN_EXTRA[sym]);
        const ds = decode(dist);
        if (ds >= 30) throw new Error('invalid distance code');
        const d = DIST_BASE[ds] + bits(DIST_EXTRA[ds]);
        if (d > o) throw new Error('distance reaches before the start of the window');
        for (let k = 0; k < len; k++) put(out[o - d]);
      }
    };
    const stored = () => {
      bitbuf = 0; bitcnt = 0;
      if (pos + 4 > input.length) throw new Error('compressed data ended early');
      const len = input[pos] | (input[pos + 1] << 8), nlen = input[pos + 2] | (input[pos + 3] << 8);
      pos += 4;
      if (len !== (~nlen & 0xffff)) throw new Error('stored block length check failed');
      if (pos + len > input.length) throw new Error('compressed data ended early');
      for (let k = 0; k < len; k++) put(input[pos++]);
    };
    const dynamic = () => {
      const nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
      if (nlen > 286 || ndist > 30) throw new Error('too many length or distance codes');
      const cl = new Uint8Array(19);
      for (let i = 0; i < ncode; i++) cl[CODE_LENGTH_ORDER[i]] = bits(3);
      const clCode = huffman(cl);
      const lengths = new Uint8Array(nlen + ndist);
      for (let i = 0; i < nlen + ndist;) {
        const sym = decode(clCode);
        if (sym < 16) { lengths[i++] = sym; continue; }
        let len = 0, rep;
        if (sym === 16) { if (!i) throw new Error('repeat with no previous length'); len = lengths[i - 1]; rep = 3 + bits(2); }
        else if (sym === 17) rep = 3 + bits(3);
        else rep = 11 + bits(7);
        if (i + rep > nlen + ndist) throw new Error('too many code lengths');
        while (rep--) lengths[i++] = len;
      }
      if (!lengths[256]) throw new Error('no end-of-block code');
      codes(huffman(lengths.subarray(0, nlen)), huffman(lengths.subarray(nlen)));
    };
    try {
      for (let last = 0; !last;) {
        if (pos >= input.length && bitcnt === 0) break;   // ended after a sync flush, not a final block
        last = bits(1);
        const type = bits(2);
        if (type === 0) stored();
        else if (type === 1) codes(fixed().lit, fixed().dist);
        else if (type === 2) dynamic();
        else throw new Error('invalid block type');
      }
    } catch (e) { error = e.message || String(e); }
    return { bytes: out.slice(start, o), history: out.slice(Math.max(0, o - WINDOW), o), error };
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

  // ---------------------------------------------------------------------------
  // Lines
  // ---------------------------------------------------------------------------

  // Lines are compared after trimming surrounding whitespace, so re-indentation or CRLF does not hide a match.
  // A "trivial" line (short, or only brackets and punctuation) can extend a run but never start one:
  // `}` or `return;` appear in every file and prove nothing on their own.
  const norm = (line) => line.trim();
  const TRIVIAL_LEN = 8;
  const isTrivial = (n) => n.length < TRIVIAL_LEN || /^[\s{}()[\];,.:'"`<>/*#=-]*$/.test(n);

  // File-reading tools often prefix every line with its number ("     1→code", "12\tcode", "  7: code", "3 | code").
  // When most non-empty lines of a view carry such a prefix, strip it and record the transform.
  const NUMBER_PREFIX = /^\s*\d+(?:→|\t| \| |: )/;
  function splitLines(text) {
    const lines = text.split('\n');
    const nonEmpty = lines.filter((l) => l.trim());
    const numbered = nonEmpty.filter((l) => NUMBER_PREFIX.test(l)).length;
    if (nonEmpty.length >= 2 && numbered >= nonEmpty.length * 0.6) {
      return { lines: lines.map((l) => l.replace(NUMBER_PREFIX, '')), stripped: true };
    }
    return { lines, stripped: false };
  }

  // Find runs of consecutive file lines that appear as consecutive lines of a view.
  // A run counts if it has at least `minAnchors` non-trivial lines, or one non-trivial line of `longLine`+ chars.
  // Runs are extended diagonally (file line i, view line j) -> (i+1, j+1); each file line keeps its 1-based number.
  const fileIndexes = new WeakMap();
  function fileIndex(file) {
    let idx = fileIndexes.get(file);
    if (!idx) {
      idx = new Map();
      file.text.split('\n').map(norm).forEach((l, i) => { if (!idx.has(l)) idx.set(l, []); idx.get(l).push(i); });
      fileIndexes.set(file, idx);
    }
    return idx;
  }
  const viewLineCache = new WeakMap();
  function viewLines(view) {
    let v = viewLineCache.get(view);
    if (!v) {
      const { lines, stripped } = splitLines(view.text);
      v = { lines: lines.map(norm), stripped };
      viewLineCache.set(view, v);
    }
    return v;
  }

  function lineRuns(file, view, { minAnchors = 2, longLine = 40 } = {}) {
    const index = fileIndex(file);
    const { lines: vlines, stripped } = viewLines(view);
    const runs = [];
    let prev = new Map();                               // file index -> run ending at (i, j-1)
    const close = (run) => {
      const ok = run.anchors >= minAnchors || (run.anchors >= 1 && run.longest >= longLine);
      if (ok) runs.push(run);
    };
    for (let j = 0; j < vlines.length; j++) {
      const line = vlines[j];
      const cur = new Map();
      const trivial = !line || isTrivial(line);
      for (const i of index.get(line) || []) {
        const before = prev.get(i - 1);
        if (!before && trivial) continue;               // trivial lines only extend
        const run = before ? { ...before } : { fileFrom: i, viewFrom: j, anchors: 0, longest: 0 };
        // a run starts on a meaningful line (trivial ones cannot start it); trailing blank lines are not claimed
        if (line) { run.fileTo = i; run.viewTo = j; }
        if (!trivial) { run.anchors++; run.longest = Math.max(run.longest, line.length); }
        cur.set(i, run);
      }
      for (const [i, run] of prev) if (!cur.has(i + 1)) close(run);
      prev = cur;
    }
    for (const run of prev.values()) close(run);
    // keep the longest runs that do not overlap in the view
    runs.sort((a, b) => (b.viewTo - b.viewFrom) - (a.viewTo - a.viewFrom) || a.fileFrom - b.fileFrom);
    const taken = [];
    for (const r of runs) if (!taken.some((t) => r.viewFrom <= t.viewTo && t.viewFrom <= r.viewTo)) taken.push(r);
    return taken.sort((a, b) => a.viewFrom - b.viewFrom).map((r) => ({
      kind: 'lines', fileId: file.id, fileName: file.name,
      fileFrom: r.fileFrom + 1, fileTo: r.fileTo + 1, lines: r.fileTo - r.fileFrom + 1,
      viewFrom: r.viewFrom + 1, viewTo: r.viewTo + 1,
      flowId: view.flowId, side: view.side, locator: view.locator,
      transforms: stripped ? [...view.transforms, 'line-numbers'] : view.transforms,
    }));
  }

  // Binary files (images, office documents, archives) have no lines. Look for the exact bytes instead:
  // the whole file, or else the longest prefix in 4 KiB steps (an upload cut by the capture limit keeps its start).
  const PREFIX_STEP = 4096;
  function byteRuns(file, view) {
    if (!file.size || file.size < 16) return [];
    const at = view.text.indexOf(file.text);
    const base = { kind: 'bytes', fileId: file.id, fileName: file.name, flowId: view.flowId, side: view.side, locator: view.locator, transforms: view.transforms };
    if (at >= 0) return [{ ...base, fileFrom: 0, fileTo: file.size, bytes: file.size, viewOffset: at, whole: true }];
    let lo = 0, hi = Math.floor((file.size - 1) / PREFIX_STEP), found = -1, foundAt = -1;
    while (lo <= hi) {                         // a shorter prefix is found whenever a longer one is: binary search works
      const mid = (lo + hi) >> 1;
      const len = Math.max(PREFIX_STEP, mid * PREFIX_STEP);
      const pos = view.text.indexOf(file.text.slice(0, len));
      if (pos >= 0) { found = len; foundAt = pos; lo = mid + 1; } else hi = mid - 1;
    }
    if (found < 0 || found > file.size) return [];
    return [{ ...base, fileFrom: 0, fileTo: found, bytes: found, viewOffset: foundAt, whole: false }];
  }

  // A distinctive file line (40+ characters) can also travel inside a longer line: a model quoting it in a sentence,
  // a tool joining lines. Whole-line runs miss that, so look for each long line as a substring and report it as a
  // 'fragment' when no run already covers it in that view.
  function fragments(file, view, covered, longLine = 40) {
    const out = [];
    const lines = file.text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = norm(lines[i]);
      if (line.length < longLine || isTrivial(line) || covered.has(i + 1)) continue;
      const at = view.text.indexOf(line);
      if (at < 0) continue;
      out.push({ kind: 'fragment', fileId: file.id, fileName: file.name, fileFrom: i + 1, fileTo: i + 1, lines: 1,
        viewFrom: lineAt(view.text, at), viewTo: lineAt(view.text, at), viewOffset: at,
        flowId: view.flowId, side: view.side, locator: view.locator, transforms: view.transforms });
    }
    return out;
  }

  // How much of each file showed up anywhere: union of matched line ranges over non-trivial lines.
  function coverage(file, matches) {
    const fileLines = file.text.split('\n').map(norm);
    const anchors = fileLines.map((l, i) => (l && !isTrivial(l) ? i + 1 : 0)).filter(Boolean);
    const covered = new Set();
    for (const m of matches) if (m.fileId === file.id && m.kind !== 'bytes') for (let n = m.fileFrom; n <= m.fileTo; n++) covered.add(n);
    const matched = anchors.filter((n) => covered.has(n)).length;
    const ranges = [];
    for (const n of [...covered].sort((a, b) => a - b)) {
      const last = ranges[ranges.length - 1];
      if (last && n === last[1] + 1) last[1] = n; else ranges.push([n, n]);
    }
    return { fileId: file.id, fileName: file.name, lines: fileLines.length, anchorLines: anchors.length, matchedAnchors: matched, ratio: anchors.length ? matched / anchors.length : 0, ranges };
  }

  // ---------------------------------------------------------------------------
  // Everything for one archive
  // ---------------------------------------------------------------------------

  async function analyze(archive, { localFiles } = {}) {
    const { views, notes } = await archiveViews(archive);
    const files = prepareFiles(localFiles || archive.localFiles);
    // only run line matching for files that share at least one non-trivial line with the view
    const owners = new Map();
    for (const f of files) if (!f.binary) for (const [line] of fileIndex(f)) if (line && !isTrivial(line)) { if (!owners.has(line)) owners.set(line, new Set()); owners.get(line).add(f); }
    let matches = [];
    for (const v of views) {
      if (v.binary) { for (const f of files) if (f.binary) matches.push(...byteRuns(f, v)); continue; }
      const candidates = new Set();
      for (const line of viewLines(v).lines) for (const f of owners.get(line) || []) candidates.add(f);
      for (const f of files) {
        if (f.binary) continue;
        const runs = candidates.has(f) ? lineRuns(f, v) : [];
        matches.push(...runs);
        const covered = new Set();
        for (const r of runs) for (let n = r.fileFrom; n <= r.fileTo; n++) covered.add(n);
        matches.push(...fragments(f, v, covered));
      }
    }
    // The same file lines in one body are often visible in several views (raw body, joined stream, the event itself).
    // Keep one per body and file range: the most specific location wins (a concrete path, then a join, then the raw body).
    const specificity = (m) => (m.locator === 'body' ? 2 : m.transforms.includes('join') ? 1 : 0);
    const key = (m) => `${m.fileId}/${m.flowId}/${m.side}/${m.fileFrom}/${m.fileTo}`;
    const best = new Map();
    for (const m of matches) { const k = key(m); if (!best.has(k) || specificity(m) < specificity(best.get(k))) best.set(k, m); }
    matches = [...best.values()];
    // a fragment only adds information when no run in any view of the same body already covers that line
    const runLines = new Set();
    for (const m of matches) if (m.kind === 'lines') for (let n = m.fileFrom; n <= m.fileTo; n++) runLines.add(`${m.fileId}/${m.flowId}/${m.side}/${n}`);
    matches = matches.filter((m) => m.kind !== 'fragment' || !runLines.has(`${m.fileId}/${m.flowId}/${m.side}/${m.fileFrom}`));
    matches.sort((a, b) => a.flowId - b.flowId || a.fileId - b.fileId || a.fileFrom - b.fileFrom);
    const coverageList = files.map((f) => {
      if (!f.binary) return coverage(f, matches);
      const best = matches.filter((m) => m.fileId === f.id).reduce((n, m) => Math.max(n, m.bytes), 0);
      return { fileId: f.id, fileName: f.name, binary: true, size: f.size, matchedBytes: best, ratio: f.size ? best / f.size : 0, ranges: best ? [[0, best]] : [] };
    });
    return {
      files: files.map((f) => ({ id: f.id, name: f.name, size: f.size, binary: f.binary })),
      viewCount: views.length,
      matches,
      canaries: findCanaries(files, views),
      coverage: coverageList,
      notes,
      bodyLimit: archive.bodyLimit || null,
      views,
    };
  }

  return { inflateRaw, analyze, byteRuns, lineRuns, fragments, coverage, splitLines, isTrivial, prepareFiles, findCanaries, search, b64ToBytes, decodeText, isMostlyText, headerValue, decompress, jsonStrings, parseSse, latin1, bodyViews, archiveViews };
});
