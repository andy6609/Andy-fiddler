// WireScope inspector UI.
//
// One file, two modes:
//   live    – served by the C++ engine on 127.0.0.1; talks to /api/* with a per-run token.
//   offline – inlined into an exported HTML report; reads window.WIRESCOPE_ARCHIVE, no network.
//
// The UI shows what was recorded (headers, bytes, timings, protocol fields) and gives tools to
// explore and compare it. It deliberately does not attach conclusions to traffic.
(() => {
  'use strict';

  const ARCHIVE = window.WIRESCOPE_ARCHIVE || null;
  const OFFLINE = Boolean(ARCHIVE);
  const POLL_MS = 1000;
  const TEXT_LIMIT = 512 * 1024;
  const HEX_PAGE = 16 * 1024;
  const STREAM_LIMIT = 1024 * 1024;

  // ---------------------------------------------------------------------------
  // Small utilities
  // ---------------------------------------------------------------------------

  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
  const pad = (n, w = 2) => String(n).padStart(w, '0');

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return `${n} B`;
    const units = ['KiB', 'MiB', 'GiB'];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
  }
  function fmtClock(ms) {
    if (!ms) return '';
    const d = new Date(ms);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }
  function fmtDate(ms) {
    if (!ms) return '';
    const d = new Date(ms);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtClock(ms)}`;
  }
  function fmtDuration(ms) {
    if (ms === undefined || ms === null || ms === '') return '';
    ms = Number(ms);
    return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
  }
  const stamp = () => {
    const d = new Date();
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  };
  const safeName = (s) => String(s || 'capture').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'capture';

  function b64ToBytes(b64) {
    const bin = atob(b64 || '');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Base64 bodies are decoded once per body object (detail objects are replaced on refetch).
  const bytesCache = new WeakMap();
  function bodyBytes(holder) {
    if (!holder) return new Uint8Array(0);
    let b = bytesCache.get(holder);
    if (!b) { b = b64ToBytes(holder.base64); bytesCache.set(holder, b); }
    return b;
  }
  const textDecoder = new TextDecoder('utf-8');
  const decodeText = (bytes) => textDecoder.decode(bytes);
  function isMostlyText(bytes) {
    const n = Math.min(bytes.length, 4096);
    if (!n) return true;
    let control = 0;
    for (let i = 0; i < n; i++) {
      const c = bytes[i];
      if (c < 9 || (c > 13 && c < 32) || c === 127) control++;
    }
    if (control > n * 0.02) return false;
    // stream:true tolerates a multi-byte character cut at the sample boundary.
    try { new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, n), { stream: true }); return true; } catch { return false; }
  }
  function headerValue(headers, name) {
    name = name.toLowerCase();
    for (const [k, v] of headers || []) if (String(k).toLowerCase() === name) return String(v);
    return '';
  }
  function tryJson(text) {
    try { return { ok: true, value: JSON.parse(text) }; } catch (e) { return { ok: false, error: e.message }; }
  }
  function download(filename, data, type = 'application/octet-stream') {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function debounce(fn, ms) {
    let t = 0;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }
  // Reads a value out of parsed JSON with a path like "delta.text" or "choices[0].delta.content".
  function pick(value, path) {
    for (const part of String(path).match(/[^.[\]]+/g) || []) {
      if (value === null || typeof value !== 'object') return undefined;
      value = value[part];
    }
    return value;
  }

  let toastTimer = 0;
  function toast(message, isError = false) {
    const el = $('#toast');
    if (!el) return;
    el.className = 'toast' + (isError ? ' error' : '');
    el.textContent = message;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), isError ? 7000 : 3000);
  }

  const ICON_PATHS = {
    list: '<path d="M4 6h16M4 12h16M4 18h10"/>',
    layers: '<path d="M12 3 3 8l9 5 9-5-9-5Z"/><path d="m3 13 9 5 9-5"/>',
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    plug: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0V8ZM12 17v4"/>',
    alert: '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>',
    grid: '<rect x="4" y="4" width="6" height="6"/><rect x="14" y="4" width="6" height="6"/><rect x="4" y="14" width="6" height="6"/><rect x="14" y="14" width="6" height="6"/>',
    arrows: '<path d="M4 8h14l-3-3M20 16H6l3 3"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    inbox: '<path d="M4 13h4l2 3h4l2-3h4M4 13l2-8h12l2 8v6H4v-6Z"/>',
  };
  const icon = (name) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;
  const LOGO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/><path d="M12 1.5v5M12 17.5v5M1.5 12h5M17.5 12h5"/></svg>';

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  const S = {
    token: '', version: '', bodyLimit: 1024 * 1024, uiPort: 0, connected: true,
    revision: 0, session: {}, flows: [], packets: [], stats: {}, capture: {}, proxy: {}, systemProxy: {},
    flowById: new Map(), packetById: new Map(),
    interfaces: null,
    view: 'flows',                       // 'flows' | 'packets' | 'find' | 'trace'
    // Trace views: search in bodies, and local files -> requests (web/provenance.js does the matching).
    trace: { fileFilter: null, query: '', caseSensitive: false, hits: null, hitsTruncated: false, analysis: null, analyzedRevision: -1, running: false, error: '' },
    category: 'all',
    connection: '',                      // flow.connection or packet.key filter
    processPid: null,                    // Windows: flow.process.pid filter
    search: { flows: '', packets: '' },
    stateFilter: '',
    visibleIds: [],
    selected: null,                      // { kind: 'flow' | 'packet', id }
    detail: null, detailKey: '',
    flowTab: 'overview', packetTab: 'fields',
    bodyMode: {}, decodeOff: {}, hexLimit: {}, sseJoin: {},
    highlight: null, stream: null, streamMode: '',
    backTo: null,                        // flow id to return to after jumping into a packet
    compare: [],                         // up to two flow ids
    cmp: { part: 'reqBody', view: 'paths', sortKeys: true, showSame: false, ignore: '', a: null, b: null },
    inspectorStale: false,
  };

  function indexRecords() {
    S.flowById = new Map(S.flows.map((f) => [f.id, f]));
    S.packetById = new Map(S.packets.map((p) => [p.id, p]));
  }

  // ---------------------------------------------------------------------------
  // Data access: live API or embedded archive
  // ---------------------------------------------------------------------------

  async function api(method, path, body, as = 'json') {
    const headers = { 'X-WireScope-Token': S.token };
    let payload;
    if (body instanceof ArrayBuffer || body instanceof Blob) { payload = body; headers['Content-Type'] = 'application/octet-stream'; }
    else if (typeof body === 'string') { payload = body; headers['Content-Type'] = 'application/json'; }
    else if (body !== undefined) { payload = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    const res = await fetch(path, { method, headers, body: payload, cache: 'no-store' });
    if (!res.ok) {
      let message = `${res.status} ${res.statusText}`;
      try { const j = await res.json(); if (j && j.error) message = j.error; } catch { /* not JSON */ }
      throw new Error(message);
    }
    if (as === 'blob') return res.blob();
    if (as === 'text') return res.text();
    return res.json();
  }

  const offline = OFFLINE ? {
    flows: new Map((ARCHIVE.flows || []).map((f) => [f.id, f])),
    packets: new Map((ARCHIVE.packets || []).map((p) => [p.id, p])),
  } : null;

  const loadFlow = (id) => (OFFLINE ? Promise.resolve(offline.flows.get(id) || null) : api('GET', `/api/flows/${id}`));
  const loadPacket = (id) => (OFFLINE ? Promise.resolve(offline.packets.get(id) || null) : api('GET', `/api/packets/${id}`));
  async function loadStream(key) {
    const dirs = OFFLINE
      ? streamPreviewLocal([...offline.packets.values()], key)
      : await api('GET', `/api/stream?key=${encodeURIComponent(key)}`);
    for (const d of dirs) for (const c of d.chunks) if (c.base64 !== undefined) { c.bytes = b64ToBytes(c.base64); delete c.base64; }
    return dirs;
  }

  // Same algorithm as streamPreview() in src/packet.cpp, for reports that carry raw packets.
  // Orders captured segments by sequence number; missing ranges stay visible as gaps.
  function streamPreviewLocal(packets, key) {
    const dirs = new Map();
    for (const p of packets) {
      if (p.key !== key || p.seq === undefined) continue;
      let d = dirs.get(p.source);
      if (!d) dirs.set(p.source, (d = { base: null, segs: [] }));
      let seq = p.seq >>> 0;
      if (String(p.flags || '').includes('SYN')) seq = (seq + 1) >>> 0;
      if (d.base === null) d.base = seq;
      const off = p.payloadOffset || 0, n = p.payloadLength || 0;
      if (!n || !p.base64) continue;
      const bytes = b64ToBytes(p.base64);
      if (off + n > bytes.length) continue;
      d.segs.push({ seq: (seq - d.base) | 0, data: bytes.subarray(off, off + n), id: p.id });
    }
    const out = [];
    for (const [source, d] of dirs) {
      d.segs.sort((a, b) => a.seq - b.seq);
      const chunks = [];
      let next = 0, first = true, total = 0;
      for (const s of d.segs) {
        if (first) { next = s.seq; first = false; }
        if (s.seq > next) chunks.push({ gap: s.seq - next });
        const skip = s.seq < next ? next - s.seq : 0;
        if (skip >= s.data.length) continue;
        const n = Math.min(s.data.length - skip, STREAM_LIMIT - total);
        chunks.push({ packet: s.id, offset: s.seq + skip, bytes: s.data.subarray(skip, skip + n) });
        total += n;
        next = s.seq + s.data.length;
        if (total >= STREAM_LIMIT) break;
      }
      out.push({ source, chunks, captured: total, limit: STREAM_LIMIT });
    }
    return out;
  }

  // Content-Encoding decoding happens in the browser and is cached per body object.
  const DECODERS = { gzip: 'gzip', 'x-gzip': 'gzip', deflate: 'deflate' };
  const decoded = new WeakMap();
  const decoding = new WeakMap();
  function decodeBody(body, encoding) {
    if (decoded.has(body)) return Promise.resolve(decoded.get(body));
    if (decoding.has(body)) return decoding.get(body);
    const job = (async () => {
      const raw = bodyBytes(body);
      let result;
      try {
        if (typeof DecompressionStream === 'undefined') throw new Error('DecompressionStream is not available in this browser');
        const ds = new DecompressionStream(DECODERS[encoding]);
        const writer = ds.writable.getWriter();
        writer.write(raw).catch(() => {});
        writer.close().catch(() => {});
        const reader = ds.readable.getReader();
        const parts = [];
        let total = 0, error = '';
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            parts.push(value); total += value.length;
          }
        } catch (e) { error = e.message || String(e); }
        const out = new Uint8Array(total);
        let o = 0;
        for (const part of parts) { out.set(part, o); o += part.length; }
        result = { bytes: out, error };
      } catch (e) {
        result = { bytes: raw, error: e.message || String(e), failed: true };
      }
      decoded.set(body, result);
      decoding.delete(body);
      return result;
    })();
    decoding.set(body, job);
    return job;
  }
  const contentEncoding = (headers) => headerValue(headers, 'content-encoding').toLowerCase().trim();

  // ---------------------------------------------------------------------------
  // Live updates
  // ---------------------------------------------------------------------------

  function applySnapshot(snap) {
    if (!snap.unchanged) {
      S.revision = snap.revision;
      S.session = snap.session || {};
      S.flows = snap.flows || [];
      S.packets = snap.packets || [];
      S.stats = snap.stats || {};
      S.localFiles = snap.localFiles || [];
      indexRecords();
    }
    if (snap.capture) S.capture = snap.capture;
    if (snap.proxy) S.proxy = snap.proxy;
    if (snap.systemProxy) S.systemProxy = snap.systemProxy;
    return !snap.unchanged;
  }

  async function refreshNow() {
    const changed = applySnapshot(await api('GET', `/api/state?revision=${S.revision}`));
    S.connected = true;
    updateToolbar();
    if (changed) {
      renderTopbar(); renderSidebar(); renderTable(); renderFooter();
      await refreshSelection();
      if (isTraceView()) scheduleAnalysis();
    }
  }

  async function poll() {
    try {
      await refreshNow();
    } catch (e) {
      if (S.connected) toast(`Engine unreachable: ${e.message}`, true);
      S.connected = false;
      updateToolbar();
    }
    setTimeout(poll, POLL_MS);
  }

  const editingInInspector = () => {
    const a = document.activeElement;
    return a && $('#inspector')?.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName);
  };

  // A selected request that is still streaming changes on every poll; refetch its detail.
  async function refreshSelection() {
    const sel = S.selected;
    if (!sel || sel.kind !== 'flow') return;
    const summary = S.flowById.get(sel.id);
    const key = summary ? JSON.stringify(summary) : '';
    if (!summary || key === S.detailKey) return;
    S.detailKey = key;
    const detail = await loadFlow(sel.id).catch(() => null);
    if (!detail || S.selected !== sel) return;
    S.detail = detail;
    if (editingInInspector()) { S.inspectorStale = true; return; }
    renderInspector(true);
  }

  function resetSelection() {
    S.selected = null; S.detail = null; S.detailKey = '';
    S.compare = []; S.backTo = null; S.connection = ''; S.processPid = null; S.highlight = null; S.stream = null;
  }

  // ---------------------------------------------------------------------------
  // Layout
  // ---------------------------------------------------------------------------

  function renderShell() {
    document.getElementById('app').innerHTML = `
      <div class="shell">
        <header class="topbar" id="topbar"></header>
        <div class="toolbar" id="toolbar"></div>
        <div class="workspace">
          <aside class="sidebar" id="sidebar"></aside>
          <main class="center" id="center"></main>
          <section class="inspector" id="inspector" aria-label="Inspector"></section>
        </div>
        <footer class="footer" id="footer"></footer>
      </div>
      <div id="overlay"></div>
      <div id="toast" class="toast hidden" role="status" aria-live="polite"></div>
      <input type="file" id="importFile" class="hidden" accept=".wscope,.json,.pcap,.pcapng,.cap">
      <input type="file" id="addFiles" class="hidden" multiple>
      <input type="file" id="addFolder" class="hidden" multiple webkitdirectory>`;
  }

  function renderAll() {
    renderTopbar(); renderToolbar(); updateToolbar(); renderSidebar();
    renderCenter(); renderTable(); renderInspector(); renderFooter();
  }

  function renderTopbar() {
    const s = S.session || {};
    $('#topbar').innerHTML = `
      <div class="brand">${LOGO}<span>WireScope</span><small>${esc(S.version)}</small></div>
      <div class="top-divider"></div>
      <div class="session-name" title="${esc(s.name)}">${esc(s.name || 'Untitled capture')}</div>
      ${s.client ? `<span class="tag" title="Client">${esc(s.client)}</span>` : ''}
      ${s.sample ? '<span class="tag" title="Generated fixtures with .example hosts, not captured traffic">synthetic sample</span>' : ''}
      <div class="spacer"></div>
      ${OFFLINE ? `<span class="offline-label">Offline report${ARCHIVE.redacted ? ' · redacted' : ''}</span>` : ''}
      <button data-action="session">Session</button>
      ${OFFLINE ? '' : '<button data-action="import">Import</button><button data-action="export">Export</button><button data-action="ca">Certificate</button>'}`;
  }

  function renderToolbar() {
    const bar = $('#toolbar');
    if (OFFLINE) {
      const s = S.session || {};
      bar.innerHTML = `
        <span class="muted small">Read-only archive · ${S.flows.length} requests · ${S.packets.length} packets</span>
        ${s.action ? `<div class="divider"></div><span class="small">Action: ${esc(s.action)}</span>` : ''}
        ${ARCHIVE.redacted ? '<div class="divider"></div><span class="small muted">Bodies, packets, query strings and credential headers were removed at export.</span>' : ''}`;
      return;
    }
    bar.innerHTML = `
      <span class="status-dot" id="proxyDot"></span><b>Proxy</b>
      <input id="proxyPort" type="number" min="1024" max="65535" value="18080" style="width:86px" aria-label="Proxy port">
      <label class="small" title="Terminate TLS with the local CA so HTTPS requests are recorded in plaintext. Off: CONNECT tunnels are relayed as encrypted bytes.">
        <input type="checkbox" id="proxyMitm" checked> Decrypt HTTPS</label>
      <button id="proxyToggle" data-action="proxy-toggle" class="primary">Start proxy</button>
      <button id="sysProxyToggle" data-action="sysproxy-toggle" class="hidden"
        title="Windows: point the current user's system proxy (WinINET) at WireScope. The previous setting is saved first and restored when you turn this off, stop the proxy or exit. Browsers and apps that read the system setting follow it; curl and Node.js CLIs do not.">Use as system proxy</button>
      <div class="divider"></div>
      <span class="status-dot" id="captureDot"></span><b>Capture</b>
      <select id="captureDevice" aria-label="Capture interface"><option value="">Loading interfaces…</option></select>
      <input id="captureFilter" type="text" placeholder="BPF filter (empty = everything)" style="width:190px" aria-label="BPF capture filter" spellcheck="false">
      <button id="captureToggle" data-action="capture-toggle">Start capture</button>
      <div class="spacer"></div>
      <span class="capture-state" id="engineState"></span>`;
  }

  function deviceName(id) {
    const match = (S.interfaces?.interfaces || []).find((i) => i.id === id);
    return match ? match.name : id;
  }

  function updateToolbar() {
    if (OFFLINE || !$('#proxyDot')) return;
    const p = S.proxy || {}, c = S.capture || {};
    $('#proxyDot').classList.toggle('on', Boolean(p.running));
    $('#captureDot').classList.toggle('on', Boolean(c.running));
    const pt = $('#proxyToggle');
    pt.textContent = p.running ? 'Stop proxy' : 'Start proxy';
    pt.classList.toggle('primary', !p.running);
    $('#proxyPort').disabled = $('#proxyMitm').disabled = Boolean(p.running);
    if (p.running) { $('#proxyPort').value = p.port; $('#proxyMitm').checked = Boolean(p.mitm); }
    const sp = S.systemProxy || {}, st = $('#sysProxyToggle');
    st.classList.toggle('hidden', !sp.supported);
    st.textContent = sp.ownedByWireScope ? 'System proxy: on' : 'Use as system proxy';
    st.classList.toggle('primary', Boolean(sp.ownedByWireScope));
    st.disabled = !sp.ownedByWireScope && !p.running;
    const ct = $('#captureToggle');
    ct.textContent = c.running ? 'Stop capture' : 'Start capture';
    ct.disabled = !c.running && c.available === false;
    $('#captureDevice').disabled = $('#captureFilter').disabled = Boolean(c.running) || c.available === false;
    const parts = [];
    if (!S.connected) parts.push('<span class="status error">engine unreachable</span>');
    if (p.running) parts.push(`proxy 127.0.0.1:${esc(p.port)} · ${esc(p.connections)} open · ${p.mitm ? 'TLS terminated' : 'TLS passthrough'}`);
    if (sp.ownedByWireScope) parts.push(`system proxy → ${esc(sp.current?.server)}`);
    if (sp.leftover) parts.push(`<span class="status error">system proxy still set by an earlier run (${esc(sp.current?.server || '?')}; saved original in ${esc(sp.backupPath)})</span> <button class="small" data-action="sysproxy-restore">Restore original</button>`);
    if (c.running) parts.push(`capture ${esc(deviceName(c.device))} · ${esc(c.received)} received · ${esc(c.dropped)} dropped by driver`);
    if (p.error) parts.push(`<span class="status error">proxy: ${esc(p.error)}</span>`);
    if (c.error) parts.push(`<span class="status error">capture: ${esc(c.error)}</span>`);
    if (!parts.length) parts.push('proxy and capture stopped');
    $('#engineState').innerHTML = parts.join(' &nbsp;|&nbsp; ');
  }

  async function loadInterfaces() {
    try { S.interfaces = await api('GET', '/api/interfaces'); } catch (e) { S.interfaces = { available: false, error: e.message, interfaces: [] }; }
    const sel = $('#captureDevice');
    if (!sel) return;
    const list = S.interfaces.interfaces || [];
    if (!S.interfaces.available) {
      sel.innerHTML = '<option value="">Capture unavailable</option>';
      sel.title = S.interfaces.error || '';
      return;
    }
    sel.innerHTML = list.map((i) => `<option value="${esc(i.id)}">${esc(i.name || i.id)}${i.loopback ? ' (loopback)' : ''}</option>`).join('')
      || '<option value="">No interfaces</option>';
    if (S.capture.device) sel.value = S.capture.device;
    sel.title = sel.value;
  }

  // ---------------------------------------------------------------------------
  // Sidebar: categories and connections
  // ---------------------------------------------------------------------------

  const KNOWN_PACKET = ['TCP', 'UDP', 'DNS', 'TLS', 'HTTP'];
  const CATEGORIES = {
    flows: [
      ['all', 'All requests', () => true, 'list'],
      ['http1', 'HTTP/1.x', (f) => /^HTTP\/1/.test(f.protocol || ''), 'arrows'],
      ['http2', 'HTTP/2', (f) => f.protocol === 'HTTP/2', 'layers'],
      ['tunnel', 'CONNECT tunnels', (f) => f.method === 'CONNECT', 'lock'],
      ['websocket', 'WebSocket', (f) => f.protocol === 'WebSocket', 'plug'],
      ['errors', 'Errors / status ≥ 400', (f) => f.state === 'error' || f.status >= 400, 'alert'],
    ],
    packets: [
      ['all', 'All packets', () => true, 'grid'],
      ['tcp', 'TCP', (p) => p.seq !== undefined, 'arrows'],
      ['udp', 'UDP', (p) => p.protocol === 'UDP' || p.protocol === 'DNS', 'arrows'],
      ['dns', 'DNS', (p) => p.protocol === 'DNS', 'globe'],
      ['tls', 'TLS records', (p) => p.protocol === 'TLS', 'lock'],
      ['http', 'Plaintext HTTP', (p) => p.protocol === 'HTTP', 'list'],
      ['other', 'Other', (p) => !KNOWN_PACKET.includes(p.protocol), 'alert'],
    ],
  };

  function connectionGroups() {
    const map = new Map();
    if (S.view === 'flows') {
      for (const f of S.flows) {
        const key = f.connection || '—';
        let g = map.get(key);
        if (!g) map.set(key, (g = { key, title: f.host || key, sub: '', count: 0 }));
        g.count++;
        if (f.method !== 'CONNECT' || !g.sub) g.sub = f.protocol || '';
      }
    } else {
      for (const p of S.packets) {
        if (!p.key) continue;
        let g = map.get(p.key);
        if (!g) map.set(p.key, (g = { key: p.key, title: p.key, sub: p.protocol, count: 0 }));
        g.count++;
      }
    }
    return [...map.values()];
  }

  // Windows builds record which process opened each proxy connection (flow.process: pid, name, ...).
  const procLabel = (p) => (p ? `${p.name || '?'} · ${p.pid ?? '?'}` : '');
  function processGroups() {
    const map = new Map();
    for (const f of S.flows) {
      if (!f.process || f.process.pid === undefined) continue;
      let g = map.get(f.process.pid);
      if (!g) map.set(f.process.pid, (g = { pid: f.process.pid, name: f.process.name || '?', count: 0 }));
      g.count++;
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }

  function renderSidebar() {
    const html = [];
    for (const view of ['flows', 'packets']) {
      const list = view === 'flows' ? S.flows : S.packets;
      const cats = view === S.view ? CATEGORIES[view] : CATEGORIES[view].slice(0, 1);
      html.push(`<div class="side-heading"><span>${view === 'flows' ? 'HTTP' : 'PACKETS'}</span></div>`);
      for (const [id, label, test, ic] of cats) {
        const active = S.view === view && S.category === id;
        let count = 0;
        for (const x of list) if (test(x)) count++;
        html.push(`<button class="side-item ${active ? 'active' : ''}" data-action="category" data-view="${view}" data-cat="${id}">${icon(ic)}<span>${esc(label)}</span><span>${count}</span></button>`);
      }
    }
    const traceCount = (S.trace.analysis?.matches.length ?? '') === '' ? '' : S.trace.analysis.matches.length + S.trace.analysis.canaries.sightings.length;
    html.push('<div class="side-heading"><span title="Search inside bodies, and trace registered local files into requests">TRACE</span></div>');
    html.push(`<button class="side-item ${S.view === 'find' ? 'active' : ''}" data-action="category" data-view="find" data-cat="all">${icon('list')}<span>Find in bodies</span><span>${S.trace.hits ? S.trace.hits.length : ''}</span></button>`);
    html.push(`<button class="side-item ${S.view === 'trace' ? 'active' : ''}" data-action="category" data-view="trace" data-cat="all">${icon('layers')}<span>Local files → requests</span><span>${traceCount}</span></button>`);
    if (isTraceView()) {
      html.push(traceSidebar());
      const s = S.session || {};
      html.push(`<div class="sidebar-footer"><b>Client</b>${esc(s.client || '—')}<br><br><b>Action</b>${esc(s.action || '—')}</div>`);
      $('#sidebar').innerHTML = html.join('');
      return;
    }
    const procs = S.view === 'flows' ? processGroups() : [];
    if (procs.length) {
      html.push(`<div class="side-heading"><span title="Owning process of the client socket, read from the Windows TCP table when the proxy accepted the connection">PROCESSES</span>${S.processPid !== null
        ? '<button class="flat small" data-action="clear-process">Clear</button>' : `<span>${procs.length}</span>`}</div>`);
      html.push('<div class="connections">');
      for (const g of procs.slice(0, 200)) {
        html.push(`<div class="connection ${g.pid === S.processPid ? 'active' : ''}" data-action="process" data-pid="${esc(g.pid)}">
          <div class="host">${esc(g.name)}</div><div class="sub">pid ${esc(g.pid)} · ${g.count}</div></div>`);
      }
      html.push('</div>');
    }
    const groups = connectionGroups();
    html.push(`<div class="side-heading"><span>CONNECTIONS</span>${S.connection
      ? '<button class="flat small" data-action="clear-connection">Clear</button>'
      : `<span>${groups.length}</span>`}</div>`);
    html.push('<div class="connections">');
    for (const g of groups.slice(0, 500)) {
      html.push(`<div class="connection ${g.key === S.connection ? 'active' : ''}" data-action="connection" data-key="${esc(g.key)}" title="${esc(g.key)}">
        <div class="host">${esc(g.title)}</div><div class="sub">${esc(g.sub)} · ${g.count} · ${esc(g.key)}</div></div>`);
    }
    if (!groups.length) html.push('<div class="connection muted small">None yet</div>');
    html.push('</div>');
    const s = S.session || {};
    html.push(`<div class="sidebar-footer"><b>Client</b>${esc(s.client || '—')}<br><br><b>Action</b>${esc(s.action || '—')}</div>`);
    $('#sidebar').innerHTML = html.join('');
  }

  function setView(view, category = 'all') {
    if (S.view !== view) { S.view = view; S.connection = ''; renderCenter(); }
    S.category = category;
    renderSidebar(); renderTable();
    if (isTraceView()) scheduleAnalysis(0);
  }
  const isTraceView = () => S.view === 'find' || S.view === 'trace';

  // ---------------------------------------------------------------------------
  // Center: request / packet table
  // ---------------------------------------------------------------------------

  function renderCenter() {
    if (isTraceView()) { renderTraceCenter(); return; }
    const flows = S.view === 'flows';
    $('#center').innerHTML = `
      <div class="center-heading">
        <h1>${flows ? 'Requests' : 'Packets'}</h1><span class="tag" id="rowCount"></span>
        <div class="spacer"></div>
        ${flows ? '<span class="muted small">Tick two rows to compare</span>' : ''}
      </div>
      <div class="searchbar">
        <input type="search" id="search" spellcheck="false" placeholder="${flows ? 'Filter by host, path, method, status, connection, process…' : 'Filter by address, port, protocol, info…'}" value="${esc(S.search[S.view])}" aria-label="Filter rows">
        ${flows ? `<select id="stateFilter" aria-label="State">${['', 'complete', 'streaming', 'pending', 'error', 'interrupted']
          .map((s) => `<option value="${s}" ${S.stateFilter === s ? 'selected' : ''}>${s || 'Any state'}</option>`).join('')}</select>` : ''}
      </div>
      <div class="table-wrap" id="tableWrap"></div>
      <div class="compare-tray hidden" id="compareTray"></div>`;
  }

  const searchCache = new WeakMap();
  function haystack(x) {
    let h = searchCache.get(x);
    if (h === undefined) {
      h = (S.view === 'flows'
        ? [x.id, x.method, x.host, x.port, x.path, x.status, x.protocol, x.state, x.error, x.notes, x.connection, x.process?.name, x.process?.pid]
        : [x.id, x.source, x.destination, x.protocol, x.summary, x.flags, x.dnsName]).join(' ').toLowerCase();
      searchCache.set(x, h);
    }
    return h;
  }

  function filteredRows() {
    const cats = CATEGORIES[S.view];
    const test = (cats.find((c) => c[0] === S.category) || cats[0])[2];
    const terms = S.search[S.view].toLowerCase().split(/\s+/).filter(Boolean);
    const list = S.view === 'flows' ? S.flows : S.packets;
    return list.filter((x) => {
      if (!test(x)) return false;
      if (S.connection && (S.view === 'flows' ? x.connection : x.key) !== S.connection) return false;
      if (S.view === 'flows' && S.stateFilter && x.state !== S.stateFilter) return false;
      if (S.view === 'flows' && S.processPid !== null && x.process?.pid !== S.processPid) return false;
      if (terms.length) { const h = haystack(x); if (!terms.every((t) => h.includes(t))) return false; }
      return true;
    });
  }

  function statusCell(f) {
    if (f.state === 'error') return `<span class="status error" title="${esc(f.error)}">ERR</span>`;
    const code = f.status ? `<span class="status ${f.status >= 400 ? 'error' : ''}">${esc(f.status)}</span>` : '';
    const state = f.state && f.state !== 'complete'
      ? `<span class="badge ${f.state === 'interrupted' ? 'warn' : ''}">${esc(f.state)}</span>` : '';
    return code && state ? `${code} ${state}` : code + state;
  }

  function flowRow(f, showProc) {
    const selected = S.selected?.kind === 'flow' && S.selected.id === f.id;
    const m = String(f.method || '').toLowerCase();
    return `<tr data-action="select-flow" data-id="${f.id}" class="${selected ? 'selected' : ''}">
      <td><input type="checkbox" data-action="compare-toggle" data-id="${f.id}" ${S.compare.includes(f.id) ? 'checked' : ''} aria-label="Compare #${f.id}"></td>
      <td class="id">${f.id}</td>
      <td><span class="method ${esc(m)}">${esc(f.method)}</span></td>
      <td><span class="target">${esc(f.host)}</span><span class="path">${esc(f.path)}</span></td>
      <td>${statusCell(f)}</td>
      ${showProc ? `<td class="small" title="${esc(f.process?.error || '')}">${f.process ? `${esc(f.process.name || '?')}<span class="path">pid ${esc(f.process.pid ?? '?')}</span>` : ''}</td>` : ''}
      <td class="mono small">${esc(f.protocol)}</td>
      <td class="mono small">↑ ${fmtBytes(f.requestBytes)}${f.truncated ? ' <span class="badge warn" title="Body larger than the ${fmtBytes(S.bodyLimit)} per-direction capture limit">cut</span>' : ''}<span class="path">↓ ${fmtBytes(f.responseBytes)}</span></td>
      <td class="mono small">${esc(fmtDuration(f.duration))}</td>
    </tr>`;
  }

  function packetRow(p) {
    const selected = S.selected?.kind === 'packet' && S.selected.id === p.id;
    return `<tr data-action="select-packet-row" data-id="${p.id}" class="${selected ? 'selected' : ''}">
      <td class="id">${p.id}</td>
      <td class="mono small">${esc(fmtClock(p.time))}</td>
      <td class="mono small">${esc(p.source)}</td>
      <td class="mono small">${esc(p.destination)}</td>
      <td><span class="badge ${p.error ? 'error' : ''}">${esc(p.protocol)}</span></td>
      <td class="mono small">${esc(p.length)}</td>
      <td class="small" title="${esc(p.summary)}">${esc(p.summary)}</td>
    </tr>`;
  }

  function emptyTable(filteredOut) {
    if (filteredOut) {
      return `<div class="empty">${icon('list')}<strong>No rows match</strong><p>The category, process, connection, state or text filter hides every row.</p>
        <div class="actions"><button data-action="clear-filters">Clear filters</button></div></div>`;
    }
    if (OFFLINE) return `<div class="empty">${icon('inbox')}<strong>Nothing in this report</strong></div>`;
    if (S.view === 'flows') {
      return `<div class="empty">${icon('inbox')}<strong>No requests recorded</strong>
        <p>Start the proxy and point a client at it (see Certificate → Client setup), or load the synthetic sample to try the inspector.</p>
        <div class="actions">${S.proxy.running ? '' : '<button class="primary" data-action="proxy-toggle">Start proxy</button>'}<button data-action="ca">Client setup</button><button data-action="sample">Load sample</button></div></div>`;
    }
    return `<div class="empty">${icon('grid')}<strong>No packets captured</strong>
      <p>Pick an interface and start capture. Client ↔ proxy traffic is on the loopback interface. You can also import a .pcap or .pcapng file.</p>
      <div class="actions"><button data-action="import">Import file</button></div></div>`;
  }

  function renderTable() {
    const wrap = $('#tableWrap');
    if (!wrap) return;
    if (isTraceView()) { renderTraceTable(); return; }
    const total = S.view === 'flows' ? S.flows.length : S.packets.length;
    const rows = filteredRows();
    S.visibleIds = rows.map((r) => r.id);
    const atBottom = wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 4;
    const top = wrap.scrollTop;
    if (!rows.length) {
      wrap.innerHTML = emptyTable(total > 0);
    } else if (S.view === 'flows') {
      const showProc = S.flows.some((f) => f.process);
      wrap.innerHTML = `<table class="traffic"><colgroup><col style="width:30px"><col style="width:42px"><col style="width:70px"><col><col style="width:64px">${showProc ? '<col style="width:104px">' : ''}<col style="width:78px"><col style="width:96px"><col style="width:66px"></colgroup>
        <thead><tr><th></th><th>#</th><th>Method</th><th>Host / path</th><th>Status</th>${showProc ? '<th title="Process that opened the proxy connection (Windows)">Process</th>' : ''}<th>Protocol</th><th>Size</th><th>Time</th></tr></thead>
        <tbody>${rows.map((f) => flowRow(f, showProc)).join('')}</tbody></table>`;
    } else {
      wrap.innerHTML = `<table class="traffic packet-table">
        <thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead>
        <tbody>${rows.map(packetRow).join('')}</tbody></table>`;
    }
    // Keep following new rows when the list was already scrolled to the end.
    wrap.scrollTop = atBottom ? wrap.scrollHeight : top;
    $('#rowCount').textContent = rows.length === total ? String(total) : `${rows.length} / ${total}`;
    renderCompareTray();
  }

  function renderCompareTray() {
    const tray = $('#compareTray');
    if (!tray) return;
    const show = S.view === 'flows' && S.compare.length > 0;
    tray.classList.toggle('hidden', !show);
    if (!show) return;
    const [a, b] = S.compare;
    tray.innerHTML = `<span>Compare <b class="mono">#${a}</b>${b ? ` ↔ <b class="mono">#${b}</b>` : ' ↔ tick one more request'}</span>
      <button class="flat" data-action="compare-clear">Clear</button>
      <button class="primary" data-action="compare-open" ${b ? '' : 'disabled'}>Compare</button>`;
  }

  function markSelectedRow() {
    for (const tr of $$('#tableWrap tr.selected')) tr.classList.remove('selected');
    if (!S.selected) return;
    const action = S.selected.kind === 'flow' ? 'select-flow' : 'select-packet-row';
    const row = $(`#tableWrap tr[data-action="${action}"][data-id="${S.selected.id}"]`);
    if (row) { row.classList.add('selected'); row.scrollIntoView({ block: 'nearest' }); }
  }

  function renderFooter() {
    const st = S.stats || {};
    const flows = st.flows ?? S.flows.length, packets = st.packets ?? S.packets.length;
    $('#footer').innerHTML = `
      <span>${flows} requests</span>
      <span>${packets} packets${st.packetWindow !== undefined && st.packetWindow < packets ? ` (table shows newest ${st.packetWindow})` : ''}</span>
      ${OFFLINE ? '' : `<span>bodies ${fmtBytes(st.bodyBytes)} · packets ${fmtBytes(st.packetBytes)} (64 MiB limit each)</span>`}
      ${st.evictedFlows || st.evictedPackets ? `<span class="status error">evicted ${st.evictedFlows} requests, ${st.evictedPackets} packets</span>` : ''}
      <div class="spacer"></div>
      <span>${OFFLINE ? `offline archive · format v${esc(ARCHIVE.version)}` : `UI 127.0.0.1:${esc(S.uiPort)} · revision ${esc(S.revision)}`}</span>`;
  }

  // ---------------------------------------------------------------------------
  // Inspector
  // ---------------------------------------------------------------------------

  const FLOW_TABS = [['overview', 'Overview'], ['request', 'Request'], ['response', 'Response'], ['timeline', 'Timeline'], ['packets', 'Packets'], ['notes', 'Notes']];
  const PACKET_TABS = [['fields', 'Fields & bytes'], ['stream', 'TCP stream'], ['raw', 'Decoded JSON']];
  let afterRender = [];

  async function select(kind, id) {
    const sel = { kind, id };
    S.selected = sel;
    S.highlight = null;
    if (kind === 'packet' && S.stream && S.packetById.get(id)?.key !== S.stream.key) S.stream = null;
    markSelectedRow();
    let detail = null;
    try { detail = kind === 'flow' ? await loadFlow(id) : await loadPacket(id); } catch (e) { toast(e.message, true); }
    if (S.selected !== sel) return; // a newer selection won
    S.detail = detail;
    S.detailKey = kind === 'flow' ? JSON.stringify(S.flowById.get(id) || '') : '';
    renderInspector();
  }

  function renderInspector(keepScroll = false) {
    const el = $('#inspector');
    const prev = $('.inspector-content', el)?.scrollTop || 0;
    afterRender = [];
    S.inspectorStale = false;
    if (!S.selected || !S.detail) {
      el.innerHTML = `<div class="empty">${icon('layers')}<strong>Nothing selected</strong>
        <p>Select a request to see its headers, bodies, timing and the packets on its connection. Select a packet to see its fields mapped onto the raw bytes.</p></div>`;
      return;
    }
    el.innerHTML = S.selected.kind === 'flow' ? flowInspector(S.detail) : S.selected.kind === 'packet' ? packetInspector(S.detail) : traceInspector(S.selected, S.detail);
    if (keepScroll) $('.inspector-content', el).scrollTop = prev;
    for (const fn of afterRender) fn();
  }

  const tabsHtml = (tabs, active, counts = {}) => `<div class="tabs" role="tablist">${tabs.map(([k, label]) =>
    `<button role="tab" data-action="tab" data-tab="${k}" class="${k === active ? 'active' : ''}">${label}${counts[k] !== undefined ? ` <span class="muted">${counts[k]}</span>` : ''}</button>`).join('')}</div>`;

  function flowUrl(f) {
    if (f.method === 'CONNECT') return f.path || '';
    if (!f.host) return f.path || '';
    const scheme = f.tls ? 'https' : 'http';
    const port = f.port && f.port !== (scheme === 'https' ? 443 : 80) ? `:${f.port}` : '';
    const host = String(f.host).includes(':') ? `[${f.host}]` : f.host;
    return `${scheme}://${host}${port}${f.path || ''}`;
  }

  function relatedPackets(f) {
    const keys = f.packetKeys || [];
    const all = OFFLINE ? [...offline.packets.values()] : S.packets;
    return keys.map((key) => ({ key, packets: all.filter((p) => p.key === key) }));
  }

  function flowInspector(f) {
    const m = String(f.method || '').toLowerCase();
    const related = relatedPackets(f).reduce((n, r) => n + r.packets.length, 0);
    let content = '';
    switch (S.flowTab) {
      case 'request': content = messageTab(f, 'request'); break;
      case 'response': content = messageTab(f, 'response'); break;
      case 'timeline': content = timelineTab(f); break;
      case 'packets': content = packetsTab(f); break;
      case 'notes': content = notesTab(f); break;
      default: content = overviewTab(f);
    }
    return `
      <div class="inspector-header">
        <div class="inspector-title"><span class="method ${esc(m)}">${esc(f.method)}</span><strong>${esc(f.host)}</strong><span class="spacer" style="flex:1"></span>${statusCell(f)}</div>
        <div class="inspector-url">${esc(flowUrl(f))}</div>
        <div class="small muted" style="margin-top:4px">#${f.id} · ${esc(f.protocol)} · ${esc(fmtDate(f.time))}${f.duration !== undefined ? ` · ${esc(fmtDuration(f.duration))}` : ''}</div>
      </div>
      ${tabsHtml(FLOW_TABS, S.flowTab, { timeline: (f.timeline || []).length, packets: related })}
      <div class="inspector-content">${content}</div>`;
  }

  // --- Overview -------------------------------------------------------------

  const META_ORDER = ['id', 'method', 'host', 'port', 'path', 'protocol', 'status', 'state', 'error', 'clientClosed', 'time', 'duration',
    'process', 'tls', 'alpn', 'cipher', 'encrypted', 'connection', 'streamId', 'upstreamStreamId', 'requestFrames', 'responseFrames',
    'requestBytes', 'responseBytes', 'truncated', 'requestTrailers', 'responseTrailers', 'packetKeys', 'source'];
  const META_HIDDEN = new Set(['request', 'response', 'timeline', 'messages', 'notes']);
  const metaRank = (k) => { const i = META_ORDER.indexOf(k); return i < 0 ? 999 : i; };

  function fmtMeta(k, v) {
    if (k === 'process' && v && typeof v === 'object') {
      const line = (label, value) => (value === undefined || value === '' ? '' : `<div><span class="muted">${esc(label)}</span> <span class="mono">${esc(value)}</span></div>`);
      return line('exe', v.name) + line('pid', v.pid) + line('path', v.path) + line('command line', v.commandLine)
        + line('parent', v.parentPid === undefined ? '' : `${v.parentName || '?'} (pid ${v.parentPid})`)
        + line('lookup error', v.error) + line('source', v.source)
        + '<div class="small muted">Read once when the proxy accepted the connection. PIDs are reused by Windows, so the parent may no longer be the process that started it.</div>';
    }
    if (k === 'time') return esc(`${fmtDate(v)}  (${v})`);
    if (k === 'duration') return esc(`${v} ms`);
    if (/Bytes$/.test(k)) return esc(`${v}  (${fmtBytes(v)})`);
    if (v !== null && typeof v === 'object') return esc(JSON.stringify(v));
    return esc(String(v));
  }

  function overviewTab(f) {
    const keys = Object.keys(f).filter((k) => !META_HIDDEN.has(k)).sort((a, b) => metaRank(a) - metaRank(b) || a.localeCompare(b));
    const bodyRow = (side) => {
      const msg = f[side] || {}, b = msg.body || {};
      return `<tr><th>${side}</th><td class="mono">${esc(b.captured ?? 0)} / ${esc(b.total ?? 0)}</td>
        <td class="mono">${esc(headerValue(msg.headers, 'content-type') || '—')}</td>
        <td class="mono">${esc(contentEncoding(msg.headers) || '—')}</td>
        <td class="mono small">${b.redacted ? 'removed at export' : esc(b.sha256 || (b.truncated ? 'not computed (truncated)' : '—'))}</td></tr>`;
    };
    return `
      <div class="section"><div class="section-title">Recorded fields</div>
        <dl class="kv">${keys.map((k) => `<dt>${esc(k)}</dt><dd>${fmtMeta(k, f[k])}</dd>`).join('')}</dl></div>
      <div class="section"><div class="section-title">Bodies</div>
        <table class="mini-table"><thead><tr><th></th><th>captured / total bytes</th><th>content-type</th><th>content-encoding</th><th>sha256 of captured bytes</th></tr></thead>
        <tbody>${bodyRow('request')}${bodyRow('response')}</tbody></table></div>`;
  }

  // --- Request / response ---------------------------------------------------

  function headersTable(headers) {
    if (!headers || !headers.length) return '<p class="muted small">None recorded.</p>';
    return `<table class="mini-table"><tbody>${headers.map(([k, v]) =>
      `<tr><th style="width:34%" class="mono">${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`).join('')}</tbody></table>`;
  }

  function messageTab(f, side) {
    const msg = f[side] || { headers: [] };
    const start = side === 'request'
      ? `${f.method} ${f.method === 'CONNECT' ? f.path : f.path} ${f.protocol === 'Tunnel' ? 'HTTP/1.1' : f.protocol}`
      : (f.status ? `${f.protocol === 'Tunnel' ? 'HTTP/1.1' : f.protocol} ${f.status}` : 'No response headers recorded');
    const trailers = f[`${side}Trailers`];
    const tunnel = f.method === 'CONNECT' && (f.encrypted || f.state !== 'complete')
      ? `<div class="notice">Bytes relayed through the CONNECT tunnel (${side === 'request' ? 'client → server' : 'server → client'}).${f.encrypted ? ' TLS was not terminated, so these are TLS records.' : ''}</div>` : '';
    return `
      <div class="section"><div class="section-title">${side === 'request' ? 'Request line' : 'Status line'}</div><pre class="code">${esc(start)}</pre></div>
      <div class="section"><div class="section-title"><span>Headers</span><span class="muted">${(msg.headers || []).length}</span></div>${headersTable(msg.headers)}</div>
      ${trailers && trailers.length ? `<div class="section"><div class="section-title"><span>Trailers</span><span class="muted">${trailers.length}</span></div>${headersTable(trailers)}</div>` : ''}
      <div class="section">${tunnel}${bodySection(f, side)}</div>`;
  }

  const MODE_LABEL = { json: 'JSON', messages: 'Messages', sse: 'Events', text: 'Text', hex: 'Hex' };
  const jsonCache = new WeakMap();
  function parsedJson(bytes) {
    if (!jsonCache.has(bytes)) jsonCache.set(bytes, bytes.length && isMostlyText(bytes) ? tryJson(decodeText(bytes)) : { ok: false });
    return jsonCache.get(bytes);
  }
  function conversationKey(v) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    for (const key of ['messages', 'contents', 'input']) {
      if (Array.isArray(v[key]) && v[key].length && v[key].every((m) => m && typeof m === 'object')) return key;
    }
    return null;
  }
  function availableModes(bytes, contentType) {
    const ct = contentType.toLowerCase();
    if (!isMostlyText(bytes)) return ['hex', 'text'];
    const head = decodeText(bytes.subarray(0, 64));
    if (ct.includes('event-stream') || /^(event|data|id):/m.test(head)) return ['sse', 'text', 'hex'];
    const j = parsedJson(bytes);
    if (j.ok) return conversationKey(j.value) ? ['json', 'messages', 'text', 'hex'] : ['json', 'text', 'hex'];
    return ['text', 'hex'];
  }

  function bodySection(f, side) {
    const msg = f[side] || {};
    const body = msg.body || {};
    const ctype = headerValue(msg.headers, 'content-type');
    const title = `<div class="section-title"><span>Body</span><span class="muted mono">${esc(ctype)}</span></div>`;
    if (body.redacted) return `${title}<div class="notice">Body removed in this redacted export (${fmtBytes(body.total)} recorded).</div>`;
    const raw = bodyBytes(body);
    if (!body.total && !raw.length) return `${title}<p class="muted small">No body bytes recorded.</p>`;

    const key = `${f.id}:${side}`;
    const encoding = contentEncoding(msg.headers);
    const decodeOn = Boolean(encoding) && !S.decodeOff[key];
    let bytes = raw, decodeNote = '';
    if (decodeOn) {
      if (!DECODERS[encoding]) {
        decodeNote = `<div class="notice">content-encoding: ${esc(encoding)} cannot be decoded in this view; showing the bytes as received.</div>`;
      } else if (!decoded.has(body)) {
        afterRender.push(() => decodeBody(body, encoding).then(() => { if (S.detail === f) renderInspector(true); }));
        return `${title}<p class="muted small">Decoding ${esc(encoding)}…</p>`;
      } else {
        const d = decoded.get(body);
        bytes = d.bytes;
        if (d.failed) decodeNote = `<div class="notice error-notice">Decoding failed: ${esc(d.error)}. Showing the bytes as received.</div>`;
        else if (d.error) decodeNote = `<div class="notice">Decoder stopped after ${fmtBytes(bytes.length)}: ${esc(d.error)}${body.truncated ? ' (the captured body is truncated)' : ''}.</div>`;
      }
    }

    const modes = availableModes(bytes, ctype);
    const mode = modes.includes(S.bodyMode[key]) ? S.bodyMode[key] : modes[0];
    const facts = [`captured ${fmtBytes(body.captured)} of ${fmtBytes(body.total)}`];
    if (decodeOn && decoded.has(body) && !decoded.get(body).failed) facts.push(`${fmtBytes(bytes.length)} after ${encoding} decoding`);
    const tools = `<div class="body-tools">
        ${modes.map((m) => `<button data-action="body-mode" data-side="${side}" data-mode="${m}" class="${m === mode ? 'active' : ''}">${MODE_LABEL[m]}</button>`).join('')}
        ${encoding ? `<label class="small" style="margin-left:6px"><input type="checkbox" data-action="decode-toggle" data-side="${side}" ${decodeOn ? 'checked' : ''}> decode ${esc(encoding)}</label>` : ''}
        <span class="spacer"></span>
        <button data-action="body-download" data-side="${side}" title="Download the captured bytes exactly as received">Download</button>
      </div>
      <div class="small muted" style="margin-bottom:8px">${facts.join(' · ')}
        ${body.truncated ? ' <span class="badge warn">truncated at ${fmtBytes(S.bodyLimit)} capture limit</span>' : ''}
        ${body.sha256 ? `<br><span class="mono">sha256 ${esc(body.sha256)}</span>` : ''}</div>`;

    let view = '';
    if (mode === 'hex') view = hexBox(bytes, { moreKey: key });
    else if (mode === 'json') view = `<pre class="code">${esc(JSON.stringify(parsedJson(bytes).value, null, 2))}</pre>`;
    else if (mode === 'messages') view = messagesView(parsedJson(bytes).value);
    else if (mode === 'sse') view = sseView(decodeText(bytes), key);
    else view = textView(decodeText(bytes));
    return title + decodeNote + tools + view;
  }

  function textView(text) {
    const cut = text.length > TEXT_LIMIT;
    return `${cut ? `<div class="notice">Showing the first ${fmtBytes(TEXT_LIMIT)} characters. Download for the rest.</div>` : ''}<pre class="code">${esc(cut ? text.slice(0, TEXT_LIMIT) : text)}</pre>`;
  }

  function hexBox(bytes, { moreKey = '', limit, highlight = null, id = '' } = {}) {
    const max = limit ?? (S.hexLimit[moreKey] || HEX_PAGE);
    const n = Math.min(bytes.length, max);
    const rows = [];
    for (let row = 0; row < n; row += 16) {
      let hex = '', ascii = '';
      for (let i = row; i < row + 16; i++) {
        if (i >= n) { hex += '<span class="hex-byte"></span>'; continue; }
        const b = bytes[i];
        const hl = highlight && i >= highlight.offset && i < highlight.offset + highlight.length ? ' highlight' : '';
        hex += `<span class="hex-byte${hl}" data-off="${i}">${HEX[b]}</span>`;
        ascii += b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
      }
      rows.push(`<div class="hex-row"><span class="hex-offset">${row.toString(16).padStart(8, '0')}</span><span>${hex}</span><span class="hex-ascii">${esc(ascii)}</span></div>`);
    }
    const more = bytes.length > n && moreKey
      ? `<button style="margin-top:8px" data-action="hex-more" data-key="${esc(moreKey)}">Show ${fmtBytes(Math.min(HEX_PAGE * 4, bytes.length - n))} more (${fmtBytes(bytes.length - n)} not shown)</button>` : '';
    const empty = bytes.length ? '' : '<span class="muted small">0 bytes</span>';
    return `<div class="hex-box"${id ? ` id="${id}"` : ''}>${rows.join('')}${empty}</div>${more}`;
  }

  // --- Server-sent events ---------------------------------------------------

  const sseCache = new Map();
  function parseSse(text) {
    if (sseCache.has(text)) return sseCache.get(text);
    const events = [];
    for (const block of text.split(/\r?\n\r?\n/)) {
      if (!block.trim()) continue;
      const ev = { event: 'message', id: '', data: [], comments: [] };
      for (const line of block.split(/\r?\n/)) {
        if (line.startsWith(':')) { ev.comments.push(line.slice(1)); continue; }
        const i = line.indexOf(':');
        const field = i < 0 ? line : line.slice(0, i);
        let value = i < 0 ? '' : line.slice(i + 1);
        if (value.startsWith(' ')) value = value.slice(1);
        if (field === 'data') ev.data.push(value);
        else if (field === 'event') ev.event = value;
        else if (field === 'id') ev.id = value;
      }
      ev.text = ev.data.join('\n');
      events.push(ev);
    }
    if (sseCache.size > 20) sseCache.clear();
    sseCache.set(text, events);
    return events;
  }
  const prettyMaybe = (text) => { const j = tryJson(text); return j.ok ? JSON.stringify(j.value, null, 2) : text; };

  function sseJoined(events, path) {
    if (!path) return '';
    const values = [];
    for (const e of events) {
      const j = tryJson(e.text);
      const v = j.ok ? pick(j.value, path) : undefined;
      if (typeof v === 'string') values.push(v);
    }
    return `<pre class="code" style="margin-top:8px">${esc(values.join(''))}</pre><div class="small muted">${values.length} string values at "${esc(path)}" joined in event order</div>`;
  }

  function sseView(text, key) {
    const events = parseSse(text);
    const counts = new Map();
    for (const e of events) counts.set(e.event, (counts.get(e.event) || 0) + 1);
    const shown = events.slice(0, 2000);
    return `
      <div class="section"><div class="section-title"><span>${events.length} events</span></div>
        <table class="mini-table"><tbody>${[...counts].map(([k, v]) => `<tr><th class="mono">${esc(k)}</th><td class="mono">${v}</td></tr>`).join('')}</tbody></table></div>
      <div class="section"><div class="section-title"><span>Join a string field across events</span></div>
        <input type="text" data-input="sse-join" data-key="${esc(key)}" value="${esc(S.sseJoin[key] || '')}" spellcheck="false"
          placeholder="Path inside each data payload, e.g. delta.text or choices[0].delta.content" style="width:100%">
        <div id="sseJoined">${sseJoined(events, S.sseJoin[key] || '')}</div></div>
      <div class="section">${shown.map((e, i) => `<div class="sse-event"><strong>#${i} ${esc(e.event)}</strong>${e.id ? ` <span class="muted small">id ${esc(e.id)}</span>` : ''}
        <pre class="code">${esc(prettyMaybe(e.text))}</pre></div>`).join('')}
        ${events.length > shown.length ? `<div class="notice">${events.length - shown.length} more events not shown.</div>` : ''}</div>`;
  }

  // --- Conversation-shaped JSON (messages / contents / input arrays) ----------

  function preview(v) {
    if (typeof v === 'string') return v.length > 300 ? `${v.slice(0, 300)}… (${v.length} chars)` : v;
    if (Array.isArray(v)) {
      const names = v.map((x) => (x && typeof x === 'object' && typeof x.name === 'string' ? x.name : null)).filter(Boolean);
      return `array(${v.length})${names.length ? `: ${names.slice(0, 30).join(', ')}` : ''}`;
    }
    if (v && typeof v === 'object') return `object{${Object.keys(v).slice(0, 12).join(', ')}}`;
    return JSON.stringify(v);
  }
  function blockHtml(b) {
    if (typeof b === 'string') return `<pre class="code" style="margin:6px 0">${esc(b)}</pre>`;
    if (!b || typeof b !== 'object') return `<pre class="code" style="margin:6px 0">${esc(JSON.stringify(b))}</pre>`;
    const type = typeof b.type === 'string' ? b.type : Object.keys(b)[0] || 'block';
    const rest = { ...b };
    delete rest.type;
    const text = typeof b.text === 'string' ? b.text : null;
    if (text !== null) delete rest.text;
    return `<div style="margin:8px 0"><span class="badge">${esc(type)}</span>
      ${text !== null ? `<pre class="code" style="margin-top:4px">${esc(text)}</pre>` : ''}
      ${Object.keys(rest).length ? `<pre class="code" style="margin-top:4px">${esc(JSON.stringify(rest, null, 2))}</pre>` : ''}</div>`;
  }
  function messagesView(v) {
    const key = conversationKey(v);
    if (!key) return '<p class="muted small">No messages / contents / input array of objects in this JSON.</p>';
    const top = Object.keys(v).filter((k) => k !== key);
    const items = v[key].map((m, i) => {
      const role = m.role ?? m.type ?? '';
      const content = m.content ?? m.parts;
      let blocks;
      if (typeof content === 'string') blocks = blockHtml(content);
      else if (Array.isArray(content)) blocks = content.map(blockHtml).join('');
      else blocks = blockHtml(m);
      const extra = Object.keys(m).filter((k) => !['role', 'content', 'parts'].includes(k) && !(k === 'type' && role === m.type));
      return `<div class="context-item"><div class="role">${esc(key)}[${i}]${role ? ` · ${esc(role)}` : ''}</div>
        ${extra.length && content !== undefined ? `<div class="small muted mono">${extra.map((k) => `${esc(k)}=${esc(preview(m[k]))}`).join('  ')}</div>` : ''}
        ${blocks}</div>`;
    }).join('');
    return `
      <div class="section"><div class="section-title"><span>Top-level fields</span><span class="muted">${top.length}</span></div>
        <table class="mini-table"><tbody>${top.map((k) => `<tr><th class="mono" style="width:30%">${esc(k)}</th><td class="mono">${esc(preview(v[k]))}</td></tr>`).join('')}</tbody></table></div>
      <div class="section"><div class="section-title"><span>${esc(key)}</span><span class="muted">${v[key].length} items</span></div>${items}</div>`;
  }

  // --- Timeline, related packets, notes --------------------------------------

  function timelineTab(f) {
    const t = f.timeline || [];
    if (!t.length) return '<p class="muted small">No events recorded.</p>';
    const t0 = t[0].time;
    return `<div class="timeline">${t.map((e) => {
      const extra = Object.entries(e).filter(([k]) => k !== 'time' && k !== 'event').map(([k, v]) => `${k}=${v}`).join(' ');
      return `<div class="timeline-row"><time title="${esc(fmtDate(e.time))}">+${e.time - t0} ms</time><span><b>${esc(e.event)}</b>${extra ? ` <span class="muted">${esc(extra)}</span>` : ''}</span></div>`;
    }).join('')}</div>
    ${t.length >= 256 ? '<div class="notice">The engine keeps at most 256 events per request.</div>' : ''}`;
  }

  function packetsTab(f) {
    const groups = relatedPackets(f);
    if (!groups.length) return '<p class="muted small">No TCP endpoints were recorded for this request (synthetic sample or failed connection).</p>';
    const labels = ['Client ↔ proxy', 'Proxy ↔ upstream'];
    const anyPackets = groups.some((g) => g.packets.length);
    return `<p class="small muted" style="margin-top:0">Packets are matched by TCP endpoint pair. One connection can carry several requests (keep-alive, HTTP/2 streams), so these lists are per connection, not per request.</p>
      ${anyPackets ? '' : `<div class="notice">No packets with these endpoints are in ${OFFLINE ? 'this report' : 'the capture window'}. Capture on the loopback interface for client ↔ proxy, or on the outbound interface for proxy ↔ upstream.</div>`}
      ${groups.map((g, i) => `<div class="section">
        <div class="section-title"><span>${labels[i] || `Endpoints ${i + 1}`}</span><span class="muted">${g.packets.length} packets</span></div>
        <div class="mono small muted" style="margin-bottom:6px">${esc(g.key)}</div>
        ${g.packets.length ? `<button data-action="stream-key" data-key="${esc(g.key)}">Follow TCP stream</button>` : ''}
        ${g.packets.slice(0, 300).map((p) => `<button class="related-button" data-action="open-packet" data-id="${p.id}">
          <span class="mono">#${p.id}</span> <span class="mono muted">${esc(fmtClock(p.time))}</span> ${esc(p.source)} → ${esc(p.destination)}
          <span class="badge">${esc(p.protocol)}</span> ${esc(p.summary)} <span class="muted">${esc(p.length)} B</span></button>`).join('')}
        ${g.packets.length > 300 ? `<div class="small muted">${g.packets.length - 300} more</div>` : ''}</div>`).join('')}`;
  }

  function notesTab(f) {
    if (OFFLINE) return f.notes ? `<pre class="code">${esc(f.notes)}</pre>` : '<p class="muted small">No notes.</p>';
    return `<div class="section"><div class="section-title">Notes for #${f.id}</div>
      <textarea id="notesText" placeholder="What you did, what you expected, what you saw">${esc(f.notes || '')}</textarea>
      <div style="margin-top:8px"><button class="primary" data-action="notes-save">Save notes</button></div></div>`;
  }

  // --- Packet inspector --------------------------------------------------------

  function packetInspector(p) {
    let content;
    if (S.packetTab === 'stream') content = streamTab(p);
    else if (S.packetTab === 'raw') {
      const copy = { ...p };
      delete copy.base64;
      content = `<pre class="code">${esc(JSON.stringify(copy, null, 2))}</pre>`;
    } else content = fieldsTab(p);
    return `
      <div class="inspector-header">
        <div class="inspector-title"><span class="method">${esc(p.protocol)}</span><strong>${esc(p.source || '—')} → ${esc(p.destination || '—')}</strong></div>
        <div class="inspector-url">${esc(p.summary)}</div>
        <div class="small muted" style="margin-top:4px">#${p.id} · ${esc(fmtDate(p.time))} · ${esc(p.captured)} of ${esc(p.length)} bytes captured · link type ${esc(p.linkType)} · ${esc(deviceName(p.device))}
          ${S.backTo ? ` · <a href="#" data-action="back-to-flow">back to request #${S.backTo}</a>` : ''}</div>
      </div>
      ${tabsHtml(PACKET_TABS, S.packetTab)}
      <div class="inspector-content">${content}</div>`;
  }

  function fieldsTab(p) {
    const fields = [...(p.fields || [])];
    if (p.payloadLength) fields.push({ name: 'Payload', value: `${p.payloadLength} bytes`, offset: p.payloadOffset, length: p.payloadLength });
    const bytes = bodyBytes(p);
    afterRender.push(() => { indexHexSpans(); applyHighlight(S.highlight); });
    return `
      ${p.error ? `<div class="notice error-notice">Decoding stopped: ${esc(p.error)}</div>` : ''}
      <div class="section"><div class="section-title"><span>Fields</span><span class="muted">hover or click to locate the bytes</span></div>
        ${fields.length ? `<table class="mini-table"><thead><tr><th>Field</th><th>Value</th><th>Offset</th><th>Length</th></tr></thead><tbody>
          ${fields.map((f) => `<tr class="field-row" data-action="field" data-off="${f.offset}" data-len="${f.length}">
            <td>${esc(f.name)}</td><td class="mono">${esc(f.value)}</td><td class="mono muted">${f.offset}</td><td class="mono muted">${f.length}</td></tr>`).join('')}
        </tbody></table>` : '<p class="muted small">No fields decoded for this link type.</p>'}</div>
      <div class="section"><div class="section-title"><span>Bytes</span><button data-action="packet-download">Download</button></div>
        ${hexBox(bytes, { limit: 65536, highlight: S.highlight, id: 'packetHex' })}</div>`;
  }

  let hexSpans = [], lit = [];
  function indexHexSpans() { hexSpans = $$('#packetHex .hex-byte[data-off]'); lit = []; }
  function applyHighlight(h) {
    for (const i of lit) hexSpans[i]?.classList.remove('highlight');
    lit = [];
    if (!h) return;
    for (let i = h.offset; i < h.offset + h.length && i < hexSpans.length; i++) { hexSpans[i].classList.add('highlight'); lit.push(i); }
  }

  function streamTab(p) {
    if (!p.key || p.seq === undefined) return '<p class="muted small">The stream view needs a TCP packet.</p>';
    if (!S.stream || S.stream.key !== p.key) {
      const key = p.key;
      afterRender.push(() => loadStream(key).then((dirs) => {
        S.stream = { key, dirs };
        if (S.selected?.kind === 'packet' && S.detail?.key === key) renderInspector(true);
      }).catch((e) => toast(e.message, true)));
      return '<p class="muted small">Loading stream…</p>';
    }
    const dirs = S.stream.dirs;
    const merged = dirs.map((d) => {
      // Contiguous chunks are shown as one block; gaps stay explicit.
      const blocks = [];
      for (const c of d.chunks) {
        if (c.gap !== undefined) { blocks.push({ gap: c.gap }); continue; }
        const last = blocks[blocks.length - 1];
        if (last && last.parts) { last.parts.push(c.bytes); last.packets.push(c.packet); } else blocks.push({ parts: [c.bytes], packets: [c.packet], offset: c.offset });
      }
      for (const b of blocks) {
        if (!b.parts) continue;
        const total = b.parts.reduce((n, x) => n + x.length, 0);
        b.bytes = new Uint8Array(total);
        let o = 0;
        for (const x of b.parts) { b.bytes.set(x, o); o += x.length; }
      }
      return { ...d, blocks };
    });
    const allText = merged.every((d) => d.blocks.every((b) => !b.bytes || isMostlyText(b.bytes)));
    const mode = S.streamMode || (allText ? 'text' : 'hex');
    return `
      <div class="body-tools">
        ${['text', 'hex'].map((m) => `<button data-action="stream-mode" data-mode="${m}" class="${m === mode ? 'active' : ''}">${MODE_LABEL[m]}</button>`).join('')}
        <span class="spacer"></span><span class="small muted mono">${esc(p.key)}</span></div>
      <p class="small muted">Captured segments ordered by sequence number. Overlapping retransmitted bytes are skipped; uncaptured ranges are shown as gaps. This is a preview, not full TCP reassembly.</p>
      ${merged.length ? '' : '<p class="muted small">No payload bytes in the captured packets.</p>'}
      ${merged.map((d) => `<div class="section"><div class="section-title"><span class="mono">${esc(d.source)} →</span>
          <span class="muted">${fmtBytes(d.captured)}${d.captured >= d.limit ? ' (preview limit reached)' : ''}</span></div>
        ${d.blocks.map((b) => (b.gap !== undefined
          ? `<div class="notice">${b.gap} bytes not captured (sequence gap)</div>`
          : `<div class="small muted mono" style="margin:6px 0 4px">stream offset ${b.offset} · packets ${b.packets.slice(0, 12).map((id) => `#${id}`).join(' ')}${b.packets.length > 12 ? ' …' : ''}</div>
             ${mode === 'hex' ? hexBox(b.bytes, { limit: 8192 }) : `<pre class="code">${esc(decodeText(b.bytes))}</pre>`}`)).join('')}
      </div>`).join('')}`;
  }

  // ---------------------------------------------------------------------------
  // Compare two requests
  // ---------------------------------------------------------------------------

  const CMP_PARTS = [['overview', 'Overview'], ['reqHeaders', 'Request headers'], ['reqBody', 'Request body'], ['resHeaders', 'Response headers'], ['resBody', 'Response body']];

  // Leaf paths of a JSON value, e.g. $.messages[2].content[0].text -> JSON-encoded leaf.
  const keyPath = (k) => (/^[A-Za-z_$][\w$-]*$/.test(k) ? `.${k}` : `[${JSON.stringify(k)}]`);
  function flatten(v, path = '$', out = new Map()) {
    if (Array.isArray(v)) {
      if (!v.length) out.set(path, '[]');
      v.forEach((x, i) => flatten(x, `${path}[${i}]`, out));
    } else if (v && typeof v === 'object') {
      const keys = Object.keys(v);
      if (!keys.length) out.set(path, '{}');
      for (const k of keys) flatten(v[k], path + keyPath(k), out);
    } else out.set(path, JSON.stringify(v));
    return out;
  }

  // "messages[*].content, metadata.user_id" -> prefix matchers; [*] is any index, * any key.
  function parseIgnore(text) {
    return String(text).split(',').map((s) => s.trim()).filter(Boolean).map((s) => {
      const p = s.startsWith('$') ? s : s.startsWith('[') ? `$${s}` : `$.${s}`;
      const any = '\u0001';
      const src = p.replace(/\[\*\]/g, any).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '[^.\\[]*').split(any).join('\\[\\d+\\]');
      return { label: s, re: new RegExp(`^${src}(?:$|[.\\[])`) };
    });
  }
  const ignored = (path, rules) => rules.some((r) => r.re.test(path));

  function withoutIgnored(v, rules, path = '$') {
    if (!rules.length) return v;
    if (Array.isArray(v)) return v.map((x, i) => withoutIgnored(x, rules, `${path}[${i}]`)).filter((_, i) => !ignored(`${path}[${i}]`, rules));
    if (v && typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v)) { const p = path + keyPath(k); if (!ignored(p, rules)) out[k] = withoutIgnored(v[k], rules, p); }
      return out;
    }
    return v;
  }
  function sortedKeys(v) {
    if (Array.isArray(v)) return v.map(sortedKeys);
    if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortedKeys(v[k])]));
    return v;
  }

  function headersObject(headers) {
    const o = {};
    for (const [k, v] of headers || []) (o[String(k).toLowerCase()] ||= []).push(v);
    for (const k of Object.keys(o)) if (o[k].length === 1) o[k] = o[k][0];
    return o;
  }

  function compareSide(f, part) {
    if (part === 'reqHeaders') return { kind: 'json', value: headersObject(f.request?.headers) };
    if (part === 'resHeaders') return { kind: 'json', value: headersObject(f.response?.headers) };
    const side = part === 'reqBody' ? 'request' : 'response';
    const msg = f[side] || {}, body = msg.body || {};
    if (body.redacted) return { kind: 'text', text: '', note: 'body removed in redacted export' };
    let bytes = bodyBytes(body), note = '';
    const enc = contentEncoding(msg.headers);
    if (enc && decoded.has(body) && !decoded.get(body).failed) { bytes = decoded.get(body).bytes; note = `compared after ${enc} decoding`; }
    if (body.truncated) note = [note, `only the first ${fmtBytes(body.captured)} were captured`].filter(Boolean).join('; ');
    if (!isMostlyText(bytes)) {
      const lines = [];
      for (let i = 0; i < Math.min(bytes.length, 256 * 1024); i += 16) lines.push(Array.from(bytes.subarray(i, i + 16), (b) => HEX[b]).join(' '));
      return { kind: 'text', text: lines.join('\n'), note: [note, 'binary, compared as hex lines'].filter(Boolean).join('; ') };
    }
    const text = decodeText(bytes);
    const j = tryJson(text);
    return j.ok ? { kind: 'json', value: j.value, note } : { kind: 'text', text, note };
  }

  // Line diff: trims the common prefix/suffix, then LCS on the middle.
  function diffLines(a, b) {
    let start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start++;
    let ea = a.length, eb = b.length;
    while (ea > start && eb > start && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
    const ops = [];
    for (let i = 0; i < start; i++) ops.push({ t: 'same', a: a[i], b: b[i] });
    const A = a.slice(start, ea), B = b.slice(start, eb);
    let approximate = false;
    if (A.length * B.length > 2_500_000) {
      approximate = true;
      for (const l of A) ops.push({ t: 'del', a: l });
      for (const l of B) ops.push({ t: 'add', b: l });
    } else {
      const n = A.length, m = B.length, w = m + 1;
      const L = new Uint32Array((n + 1) * w);
      for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) {
        L[i * w + j] = A[i] === B[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
      }
      let i = 0, j = 0;
      while (i < n && j < m) {
        if (A[i] === B[j]) { ops.push({ t: 'same', a: A[i++], b: B[j++] }); }
        else if (L[(i + 1) * w + j] >= L[i * w + j + 1]) ops.push({ t: 'del', a: A[i++] });
        else ops.push({ t: 'add', b: B[j++] });
      }
      while (i < n) ops.push({ t: 'del', a: A[i++] });
      while (j < m) ops.push({ t: 'add', b: B[j++] });
    }
    for (let i = ea; i < a.length; i++) ops.push({ t: 'same', a: a[i], b: b[i - ea + eb] });
    return { ops, approximate };
  }

  function sideBySide(textA, textB, labelA, labelB) {
    const { ops, approximate } = diffLines(textA.split('\n'), textB.split('\n'));
    const rows = [];
    let la = 0, lb = 0, i = 0;
    const cell = (cls, n, text, border) => `<div class="diff-line ${cls}"${border ? ' style="border-left:1px solid var(--line)"' : ''}><span>${n}</span>${esc(text)}</div>`;
    while (i < ops.length) {
      if (ops[i].t === 'same') {
        let j = i;
        while (j < ops.length && ops[j].t === 'same') j++;
        const run = j - i, context = 3;
        const collapse = !S.cmp.showSame && run > context * 2 + 2;
        for (let k = i; k < j; k++) {
          const idx = k - i;
          if (collapse && idx >= (i === 0 ? 0 : context) && idx < run - (j === ops.length ? 0 : context)) {
            if (idx === (i === 0 ? 0 : context)) {
              const hidden = run - (i === 0 ? 0 : context) - (j === ops.length ? 0 : context);
              rows.push(`<div style="display:grid;grid-template-columns:1fr 1fr"><div class="diff-line blank" style="color:var(--muted)">… ${hidden} unchanged lines</div><div class="diff-line blank" style="color:var(--muted);border-left:1px solid var(--line)">… ${hidden} unchanged lines</div></div>`);
            }
            la++; lb++;
            continue;
          }
          rows.push(`<div style="display:grid;grid-template-columns:1fr 1fr">${cell('', ++la, ops[k].a)}${cell('', ++lb, ops[k].b, true)}</div>`);
        }
        i = j;
        continue;
      }
      const dels = [], adds = [];
      while (i < ops.length && ops[i].t !== 'same') { (ops[i].t === 'del' ? dels : adds).push(ops[i]); i++; }
      for (let k = 0; k < Math.max(dels.length, adds.length); k++) {
        rows.push(`<div style="display:grid;grid-template-columns:1fr 1fr">${k < dels.length ? cell('remove', ++la, dels[k].a) : cell('blank', '', '')}${k < adds.length ? cell('add', ++lb, adds[k].b, true) : cell('blank', '', '', true)}</div>`);
      }
    }
    const shown = rows.slice(0, 20000);
    return `${approximate ? '<div class="notice" style="margin:10px 12px">Too many differing lines for an aligned diff; the changed region is shown as removed then added.</div>' : ''}
      <div class="diff-panels" style="display:block">
        <div style="display:grid;grid-template-columns:1fr 1fr;position:sticky;top:0;z-index:1"><div class="diff-label">${esc(labelA)}</div><div class="diff-label" style="border-left:1px solid var(--line)">${esc(labelB)}</div></div>
        ${shown.join('')}
        ${rows.length > shown.length ? `<div class="notice" style="margin:10px 12px">${rows.length - shown.length} more rows not shown.</div>` : ''}
      </div>`;
  }

  function pathTable(va, vb, rules, a, b) {
    const fa = flatten(va), fb = flatten(vb);
    const paths = [...fa.keys(), ...[...fb.keys()].filter((p) => !fa.has(p))];
    const counts = { added: 0, removed: 0, changed: 0, same: 0, ignored: 0 };
    const rows = [];
    const KIND_STYLE = { added: 'background:#e3f3e9;color:#236446', removed: 'background:#fbe6e8;color:#99424c', changed: 'background:#fff0d6;color:#8d641c', same: '' };
    const cut = (s) => (s === undefined ? '' : s.length > 400 ? `${s.slice(0, 400)}…` : s);
    for (const p of paths) {
      if (ignored(p, rules)) { counts.ignored++; continue; }
      const x = fa.get(p), y = fb.get(p);
      const kind = x === undefined ? 'added' : y === undefined ? 'removed' : x === y ? 'same' : 'changed';
      counts[kind]++;
      if (kind === 'same' && !S.cmp.showSame) continue;
      if (rows.length < 5000) {
        rows.push(`<tr><td><span class="badge" style="${KIND_STYLE[kind]}">${kind}</span></td><td class="mono">${esc(p)}</td><td class="mono">${esc(cut(x))}</td><td class="mono">${esc(cut(y))}</td></tr>`);
      }
    }
    return `<div class="small" style="padding:10px 12px">${counts.added} added · ${counts.removed} removed · ${counts.changed} changed · ${counts.same} unchanged
        ${counts.ignored ? ` · ${counts.ignored} ignored by: ${rules.map((r) => `<span class="mono">${esc(r.label)}</span>`).join(', ')}` : ''}
        <span class="muted"> — leaf paths from #${a.id} to #${b.id}; arrays compare by index</span></div>
      <div style="overflow:auto;flex:1;min-height:0;padding:0 12px 12px">
        ${rows.length ? `<table class="mini-table"><thead><tr><th style="width:80px">change</th><th style="width:34%">path</th><th>#${a.id}</th><th>#${b.id}</th></tr></thead><tbody>${rows.join('')}</tbody></table>`
          : '<p class="muted small">No differences at the compared paths.</p>'}</div>`;
  }

  function overviewCompare(a, b) {
    const fields = [
      ['method', (f) => f.method], ['url', flowUrl], ['protocol', (f) => f.protocol], ['status', (f) => f.status],
      ['state', (f) => f.state], ['error', (f) => f.error], ['alpn', (f) => f.alpn], ['tls', (f) => f.tls],
      ['process', (f) => procLabel(f.process)], ['command line', (f) => f.process?.commandLine],
      ['connection', (f) => f.connection], ['stream id', (f) => f.streamId], ['started', (f) => fmtDate(f.time)],
      ['duration ms', (f) => f.duration], ['request headers', (f) => (f.request?.headers || []).length],
      ['response headers', (f) => (f.response?.headers || []).length], ['request bytes', (f) => f.requestBytes],
      ['response bytes', (f) => f.responseBytes], ['request sha256', (f) => f.request?.body?.sha256],
      ['response sha256', (f) => f.response?.body?.sha256], ['timeline events', (f) => (f.timeline || []).length],
      ['request frames', (f) => f.requestFrames], ['response frames', (f) => f.responseFrames],
    ];
    return `<div style="overflow:auto;padding:12px"><table class="mini-table"><thead><tr><th style="width:160px"></th><th>#${a.id}</th><th>#${b.id}</th></tr></thead><tbody>
      ${fields.map(([label, get]) => {
        const x = get(a), y = get(b);
        const differ = String(x ?? '') !== String(y ?? '');
        return `<tr${differ ? ' style="background:#fff9ec"' : ''}><th>${esc(label)}</th><td class="mono">${esc(x ?? '')}</td><td class="mono">${esc(y ?? '')}</td></tr>`;
      }).join('')}</tbody></table>
      <p class="small muted">Highlighted rows differ.</p></div>`;
  }

  function compareContent() {
    const { a, b, part } = S.cmp;
    if (part === 'overview') return overviewCompare(a, b);
    const A = compareSide(a, part), B = compareSide(b, part);
    const rules = parseIgnore(S.cmp.ignore);
    const notes = [];
    if (A.note) notes.push(`#${a.id}: ${A.note}`);
    if (B.note) notes.push(`#${b.id}: ${B.note}`);
    let html = '';
    if (S.cmp.view === 'paths' && A.kind === 'json' && B.kind === 'json') {
      html = pathTable(A.value, B.value, rules, a, b);
    } else {
      if (S.cmp.view === 'paths') notes.push('Path view needs JSON on both sides; showing the line diff.');
      const normalize = (v) => { let x = withoutIgnored(v, rules); if (S.cmp.sortKeys) x = sortedKeys(x); return JSON.stringify(x, null, 2); };
      const ta = A.kind === 'json' ? normalize(A.value) : A.text;
      const tb = B.kind === 'json' ? normalize(B.value) : B.text;
      const applied = [];
      if ((A.kind === 'json' || B.kind === 'json') && S.cmp.sortKeys) applied.push('object keys sorted');
      if ((A.kind === 'json' || B.kind === 'json') && rules.length) applied.push(`ignored: ${rules.map((r) => r.label).join(', ')}`);
      if (applied.length) notes.push(`Normalized before diff: ${applied.join('; ')}.`);
      html = `<div style="overflow:auto;flex:1;min-height:0">${sideBySide(ta, tb, `#${a.id} ${a.method} ${a.host}${a.path}`, `#${b.id} ${b.method} ${b.host}${b.path}`)}</div>`;
    }
    return `${notes.length ? `<div class="notice" style="margin:10px 12px 0">${notes.map(esc).join('<br>')}</div>` : ''}${html}`;
  }

  function renderCompare() {
    const { a, b } = S.cmp;
    const btn = (action, attr, value, label, active) => `<button data-action="${action}" data-${attr}="${value}" class="${active ? 'primary' : ''}">${label}</button>`;
    const toolbar = `<div class="diff-toolbar">
        ${CMP_PARTS.map(([k, l]) => btn('cmp-part', 'part', k, l, S.cmp.part === k)).join('')}
        <div class="divider"></div>
        ${btn('cmp-view', 'view', 'paths', 'Paths', S.cmp.view === 'paths')}${btn('cmp-view', 'view', 'lines', 'Side by side', S.cmp.view === 'lines')}
        <label class="small"><input type="checkbox" data-action="cmp-sort" ${S.cmp.sortKeys ? 'checked' : ''}> Sort keys (side by side)</label>
        <label class="small"><input type="checkbox" data-action="cmp-same" ${S.cmp.showSame ? 'checked' : ''}> Show unchanged</label>
        <input type="text" id="cmpIgnore" spellcheck="false" placeholder="Ignore paths, e.g. metadata.user_id, messages[*].content" value="${esc(S.cmp.ignore)}" style="flex:1;min-width:220px">
      </div>`;
    openDialog(`Compare #${a.id} ↔ #${b.id}`, `${toolbar}<div id="cmpContent" style="flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden">${compareContent()}</div>`, '', true);
  }

  async function openCompare() {
    const [ia, ib] = S.compare;
    const [a, b] = await Promise.all([loadFlow(ia), loadFlow(ib)]);
    if (!a || !b) throw new Error('A selected request is no longer in the session');
    // Decode compressed bodies first so the diff sees the same bytes the inspector shows.
    const jobs = [];
    for (const f of [a, b]) for (const side of ['request', 'response']) {
      const enc = contentEncoding(f[side]?.headers);
      if (enc && DECODERS[enc] && f[side]?.body && !f[side].body.redacted) jobs.push(decodeBody(f[side].body, enc));
    }
    await Promise.all(jobs);
    Object.assign(S.cmp, { a, b });
    renderCompare();
  }

  // ---------------------------------------------------------------------------
  // Trace: find in bodies, local files -> requests
  // ---------------------------------------------------------------------------
  //
  // The matching itself lives in web/provenance.js (shared with node scripts and tests). This part only loads
  // the full archive, runs the analysis, and draws it. A match says "these bytes were in this request as captured";
  // it does not say which process read the file.

  const PROV = window.WireScopeProvenance || null;

  // Live mode needs the bodies of every request, so it reads the same archive a session export gives.
  async function traceArchive() {
    if (OFFLINE) return ARCHIVE;
    return JSON.parse(await api('GET', '/api/session/download', undefined, 'text'));
  }

  let analysisTimer = 0;
  function scheduleAnalysis(delay = 800) {
    clearTimeout(analysisTimer);
    analysisTimer = setTimeout(() => runAnalysis(), delay);
  }

  async function runAnalysis(force = false) {
    const T = S.trace;
    if (!PROV) { T.error = 'provenance.js is not loaded'; renderTraceTable(); return; }
    if (T.running || (!force && T.analysis && T.analyzedRevision === S.revision)) return;
    T.running = true;
    renderTraceTable();
    const revision = S.revision;
    try {
      T.analysis = await PROV.analyze(await traceArchive());
      T.analyzedRevision = revision;
      T.error = '';
      if (T.query) runSearch();
    } catch (e) {
      T.error = e.message || String(e);
    } finally {
      T.running = false;
    }
    if (isTraceView()) { renderSidebar(); renderTable(); }
  }

  function runSearch() {
    const T = S.trace;
    if (!T.analysis) return;
    const r = PROV.search(T.analysis.views, T.query, { caseSensitive: T.caseSensitive });
    T.hits = T.query ? r.hits : null;
    T.hitsTruncated = r.truncated;
  }

  // Local file snapshots: what to trace. Live mode adds them from the browser (the engine never opens paths itself).
  function traceSidebar() {
    const files = S.localFiles || [];
    const cov = new Map((S.trace.analysis?.coverage || []).map((c) => [c.fileId, c]));
    const head = `<div class="side-heading"><span title="Snapshots of files to look for in captured bodies">LOCAL FILES</span>${OFFLINE ? `<span>${files.length}</span>`
      : '<span><button class="flat small" data-action="files-add" title="Add files">+ files</button><button class="flat small" data-action="folder-add" title="Add a folder (skips .git and node_modules)">+ folder</button></span>'}</div>`;
    if (!files.length) {
      return `${head}<div class="connections"><div class="connection muted small">${OFFLINE ? 'No local files in this report.' : 'Add the files of your experiment repo. Snapshots stay in this session.'}</div></div>`;
    }
    const rows = files.map((f) => {
      const c = cov.get(f.id);
      const share = c ? (c.binary ? (c.matchedBytes ? `${Math.round(c.ratio * 100)}% bytes` : 'not seen') : `${c.matchedAnchors}/${c.anchorLines} lines`) : '';
      const active = S.trace.fileFilter === f.id;
      return `<div class="connection ${active ? 'active' : ''}" data-action="trace-file" data-id="${f.id}" title="${esc(f.name)} · sha256 ${esc(f.sha256 || '')}">
        <div class="host">${esc(f.name)}</div>
        <div class="sub">${fmtBytes(f.size)}${share ? ` · ${esc(share)}` : ''}${OFFLINE ? '' : ` · <a href="#" data-action="file-remove" data-id="${f.id}">remove</a>`}</div></div>`;
    }).join('');
    return `${head}<div class="connections">${rows}</div>`;
  }

  const MAX_SNAPSHOT = 2 * 1024 * 1024;
  async function addLocalFiles(list) {
    const skipped = { big: 0, ignored: 0 };
    let added = 0;
    for (const file of list) {
      const name = file.webkitRelativePath || file.name;
      if (/(^|\/)(\.git|node_modules)\//.test(name)) { skipped.ignored++; continue; }
      if (file.size > MAX_SNAPSHOT) { skipped.big++; continue; }
      const bytes = new Uint8Array(await file.arrayBuffer());
      let bin = '';
      for (let i = 0; i < bytes.length; i += 8192) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
      await api('POST', '/api/files', { name, base64: btoa(bin), origin: 'browser' });
      added++;
    }
    const extra = [skipped.big && `${skipped.big} over 2 MiB skipped`, skipped.ignored && `${skipped.ignored} in .git/node_modules skipped`].filter(Boolean).join(', ');
    toast(`Added ${added} file${added === 1 ? '' : 's'}${extra ? ` (${extra})` : ''}`);
    await refreshNow();
    runAnalysis(true);
  }

  function renderTraceCenter() {
    const find = S.view === 'find';
    $('#center').innerHTML = `
      <div class="center-heading">
        <h1>${find ? 'Find in bodies' : 'Local files → requests'}</h1><span class="tag" id="rowCount"></span>
        <div class="spacer"></div>
        <button class="flat" data-action="trace-rerun" title="Read the session again and redo the analysis">Re-run</button>
      </div>
      ${find ? `<div class="searchbar">
        <input type="search" id="traceQuery" spellcheck="false" placeholder="Text to find in request and response bodies, e.g. WSCANARY-" value="${esc(S.trace.query)}" aria-label="Find in bodies">
        <label class="small trace-case"><input type="checkbox" data-action="trace-case" ${S.trace.caseSensitive ? 'checked' : ''}> Match case</label>
      </div>` : ''}
      <div class="table-wrap" id="tableWrap"></div>`;
  }

  const transformBadges = (t) => (t.length ? t.map((x) => `<span class="badge">${esc(x)}</span>`).join(' ') : '<span class="muted small">as captured</span>');
  const sideLabel = (side) => (side === 'request' ? '↑ request' : '↓ response');
  function flowLabel(id) {
    const f = S.flowById.get(id) || (S.trace.analysis ? null : null);
    return f ? `<span class="method ${esc(String(f.method || '').toLowerCase())}">${esc(f.method)}</span> <span class="path" style="display:inline">${esc(f.host)}${esc(f.path)}</span>` : '';
  }
  function excerptHtml(x) {
    const cls = x.hex ? ' class="mono"' : '';
    return `<span${cls}>${esc(x.before)}<mark>${esc(x.match)}</mark>${esc(x.after)}</span>`;
  }

  function findTable() {
    const T = S.trace;
    if (!T.query) {
      return `<div class="empty">${icon('list')}<strong>Search inside every body</strong>
        <p>Bodies are searched after undoing gzip/deflate, JSON escaping, SSE framing, base64 and multipart, so text that left in a JSON string or an attachment is found as you would type it.</p></div>`;
    }
    if (!T.hits || !T.hits.length) return `<div class="empty">${icon('list')}<strong>No body contains “${esc(T.query)}”</strong>${limitsNotice()}</div>`;
    return `${T.hitsTruncated ? '<div class="notice" style="margin:10px 12px 0">Too many hits; the list is cut. Narrow the search.</div>' : ''}
      <table class="traffic"><colgroup><col style="width:74px"><col style="width:88px"><col style="width:28%"><col style="width:110px"><col></colgroup>
      <thead><tr><th>Request</th><th>Side</th><th>Where</th><th>How</th><th>Context</th></tr></thead>
      <tbody>${T.hits.map((h, i) => `<tr data-action="trace-hit" data-i="${i}" class="${S.selected?.kind === 'hit' && S.selected.id === i ? 'selected' : ''}">
        <td class="id">#${h.flowId}</td><td class="small">${sideLabel(h.side)}</td><td class="mono small" title="${esc(h.locator)}">${esc(h.locator)}</td>
        <td class="small">${transformBadges(h.transforms)}</td><td class="small trace-excerpt">${excerptHtml(h.excerpt)}</td></tr>`).join('')}</tbody></table>`;
  }

  // What the analysis could not look at, said plainly next to the results.
  function limitsNotice() {
    const a = S.trace.analysis;
    if (!a) return '';
    const items = [];
    if (a.bodyLimit) items.push(`Only the first ${fmtBytes(a.bodyLimit)} of each body is captured, so bytes past that are never searched.`);
    const cut = a.notes.filter((n) => /only the first/.test(n.note)).length;
    if (cut) items.push(`${cut} bodies were cut at that limit.`);
    for (const n of a.notes.filter((x) => !/only the first/.test(x.note)).slice(0, 5)) items.push(`#${n.flowId} ${n.side}: ${n.note}`);
    return items.length ? `<div class="notice trace-limits">${items.map(esc).join('<br>')}</div>` : '';
  }

  function traceStatus() {
    const T = S.trace;
    if (T.error) return `<div class="notice error-notice">${esc(T.error)}</div>`;
    if (T.running && !T.analysis) return '<p class="muted small" style="padding:16px">Reading the session and decoding bodies…</p>';
    return '';
  }

  function renderTraceTable() {
    const wrap = $('#tableWrap');
    if (!wrap || !isTraceView()) return;
    const status = traceStatus();
    if (status) { wrap.innerHTML = status; return; }
    if (S.view === 'find') {
      wrap.innerHTML = findTable();
      $('#rowCount').textContent = S.trace.hits ? String(S.trace.hits.length) : '';
      return;
    }
    wrap.innerHTML = provenanceTables();
    $('#rowCount').textContent = S.trace.analysis ? String(traceMatches().length) : '';
  }

  const traceMatches = () => (S.trace.analysis?.matches || []).filter((m) => S.trace.fileFilter === null || m.fileId === S.trace.fileFilter);
  const fileRange = (m) => (m.kind === 'bytes' ? `${m.whole ? 'whole file' : 'first ' + fmtBytes(m.bytes)}` : m.fileFrom === m.fileTo ? `line ${m.fileFrom}` : `lines ${m.fileFrom}–${m.fileTo}`);
  const rangeText = (c) => (c.binary ? (c.matchedBytes ? `bytes 0–${c.matchedBytes}` : '—') : c.ranges.map(([a, b]) => (a === b ? `${a}` : `${a}–${b}`)).join(', ') || '—');

  function provenanceTables() {
    const a = S.trace.analysis;
    if (!a) return '';
    if (!a.files.length) {
      return `<div class="empty">${icon('layers')}<strong>No local files registered</strong>
        <p>Add the files of your experiment repository. Each request and response body is then checked for runs of their lines (or their exact bytes, for binary files) and for planted canary tokens.</p>
        ${OFFLINE ? '' : '<div class="actions"><button class="primary" data-action="folder-add">Add a folder</button><button data-action="files-add">Add files</button></div>'}</div>`;
    }
    const canaries = a.canaries;
    const perFile = (id) => {
      const tokens = canaries.sightings.filter((x) => x.from.some((f) => f.fileId === id)).length;
      const missing = canaries.notSeen.filter((x) => x.from.some((f) => f.fileId === id)).length;
      return { tokens, missing };
    };
    const coverageRows = a.coverage.map((c) => {
      const reqs = [...new Set(a.matches.filter((m) => m.fileId === c.fileId).map((m) => m.flowId))];
      const k = perFile(c.fileId);
      const share = c.binary ? (c.matchedBytes ? `${Math.round(c.ratio * 100)}% of bytes` : 'not seen') : `${c.matchedAnchors} / ${c.anchorLines} lines`;
      return `<tr class="${S.trace.fileFilter === c.fileId ? 'selected' : ''}" data-action="trace-file" data-id="${c.fileId}">
        <td class="small" title="${esc(c.fileName)}">${esc(c.fileName)}</td><td class="mono small">${esc(share)}</td>
        <td class="mono small">${esc(rangeText(c))}</td>
        <td class="mono small">${k.tokens ? `${k.tokens} seen` : ''}${k.missing ? `${k.tokens ? ', ' : ''}${k.missing} not seen` : ''}${!k.tokens && !k.missing ? '—' : ''}</td>
        <td class="mono small">${reqs.length ? reqs.map((id) => `#${id}`).join(' ') : '—'}</td></tr>`;
    }).join('');
    const matches = traceMatches();
    const matchRows = matches.map((m, i) => `<tr data-action="trace-match" data-i="${i}" class="${S.selected?.kind === 'match' && S.selected.id === i ? 'selected' : ''}">
      <td class="small" title="${esc(m.fileName)}">${esc(m.fileName)}</td><td class="mono small">${esc(fileRange(m))}</td>
      <td class="id">#${m.flowId}</td><td class="small">${sideLabel(m.side)}</td>
      <td class="mono small" title="${esc(m.locator)}">${esc(m.locator)}</td><td class="small">${transformBadges(m.transforms)}</td></tr>`).join('');
    const canaryRows = [
      ...canaries.sightings.map((x, i) => `<tr data-action="trace-canary" data-i="${i}" class="${S.selected?.kind === 'canary' && S.selected.id === i ? 'selected' : ''}">
        <td class="mono small">${esc(x.token)}</td><td class="small">${x.from.length ? x.from.map((f) => esc(`${f.fileName}${f.line ? `:${f.line}` : ''}`)).join(', ') : '<span class="badge warn">not in any local file</span>'}</td>
        <td class="mono small">#${x.flowId} ${sideLabel(x.side)}</td><td class="mono small" title="${esc(x.locator)}">${esc(x.locator)}</td></tr>`),
      ...canaries.notSeen.map((x) => `<tr><td class="mono small">${esc(x.token)}</td><td class="small">${x.from.map((f) => esc(`${f.fileName}${f.line ? `:${f.line}` : ''}`)).join(', ')}</td>
        <td class="small muted" colspan="2">not seen in any captured body</td></tr>`),
    ].join('');
    return `
      <div class="trace-section"><div class="section-title"><span>Coverage per file</span><span class="muted">meaningful lines (not blank, not just brackets) that appeared in a run</span></div>
        <table class="traffic"><colgroup><col style="width:30%"><col style="width:120px"><col><col style="width:110px"><col style="width:120px"></colgroup>
        <thead><tr><th>File</th><th>Seen</th><th>Ranges</th><th>Canaries</th><th>Requests</th></tr></thead><tbody>${coverageRows}</tbody></table></div>
      <div class="trace-section"><div class="section-title"><span>Matches${S.trace.fileFilter !== null ? ' for the selected file' : ''}</span><span class="muted">${matches.length}</span></div>
        ${matches.length ? `<table class="traffic"><colgroup><col style="width:22%"><col style="width:96px"><col style="width:58px"><col style="width:88px"><col><col style="width:150px"></colgroup>
        <thead><tr><th>File</th><th>Part</th><th>Request</th><th>Side</th><th>Where</th><th>How</th></tr></thead><tbody>${matchRows}</tbody></table>`
          : '<p class="muted small" style="padding:0 12px">No run of lines or bytes from these files was found in any captured body.</p>'}</div>
      ${canaryRows ? `<div class="trace-section"><div class="section-title"><span>Canary tokens</span><span class="muted">WSCANARY-… markers planted in files</span></div>
        <table class="traffic"><colgroup><col style="width:190px"><col style="width:26%"><col style="width:150px"><col></colgroup>
        <thead><tr><th>Token</th><th>From</th><th>Seen in</th><th>Where</th></tr></thead><tbody>${canaryRows}</tbody></table></div>` : ''}
      ${limitsNotice()}`;
  }

  function traceList(kind = S.view === 'find' ? 'hit' : 'match') {
    if (kind === 'hit') return S.trace.hits || [];
    if (kind === 'canary') return S.trace.analysis?.canaries.sightings || [];
    return traceMatches();
  }

  function selectTrace(kind, i) {
    const item = traceList(kind)[i];
    if (!item) return;
    S.selected = { kind, id: i };
    S.detail = item;
    for (const tr of $$('#tableWrap tr.selected')) tr.classList.remove('selected');
    const row = $(`#tableWrap tr[data-action="trace-${kind}"][data-i="${i}"]`);
    if (row) { row.classList.add('selected'); row.scrollIntoView({ block: 'nearest' }); }
    renderInspector();
  }
  function moveTraceSelection(delta) {
    const list = traceList();
    if (!list.length) return;
    const kind = S.view === 'find' ? 'hit' : 'match';
    const cur = S.selected?.kind === kind ? S.selected.id : -1;
    selectTrace(kind, cur < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.max(0, Math.min(list.length - 1, cur + delta)));
  }

  function traceInspector(sel, item) {
    if (sel.kind === 'hit') return hitInspector(item);
    return '';
  }

  function hitInspector(h) {
    return `
      <div class="inspector-header">
        <div class="inspector-title"><strong>Found in request #${h.flowId}</strong></div>
        <div class="inspector-url">${flowLabel(h.flowId)}</div>
      </div>
      <div class="inspector-content">
        <dl class="kv">
          <dt>side</dt><dd>${esc(h.side)}</dd>
          <dt>where</dt><dd>${esc(h.locator)}</dd>
          <dt>how</dt><dd>${transformBadges(h.transforms)}</dd>
          <dt>offset</dt><dd>${esc(h.offset)} in that view${h.binary ? ' (bytes)' : ' (characters)'}</dd>
        </dl>
        <div class="section" style="margin-top:14px"><div class="section-title">Context</div><pre class="code">${excerptHtml(h.excerpt)}</pre></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="primary" data-action="trace-open-flow" data-id="${h.flowId}" data-side="${h.side}">Open request #${h.flowId}</button>
          <button data-action="trace-open-packets" data-id="${h.flowId}">Packets on its connection</button>
        </div>
      </div>`;
  }

  // ---------------------------------------------------------------------------
  // Dialogs
  // ---------------------------------------------------------------------------

  function openDialog(title, body, footer = '', wide = false) {
    const style = wide ? ' style="width:96vw;height:92vh;max-height:92vh;display:flex;flex-direction:column;overflow:hidden"' : '';
    $('#overlay').innerHTML = `<div class="dialog-overlay" data-action="overlay">
      <div class="dialog" role="dialog" aria-modal="true" aria-label="${esc(title)}"${style}>
        <div class="dialog-header"><h2>${esc(title)}</h2><button class="flat" data-action="dialog-close" aria-label="Close">✕</button></div>
        ${wide ? body : `<div class="dialog-body">${body}</div>`}
        ${footer ? `<div class="dialog-footer">${footer}</div>` : ''}
      </div></div>`;
    const first = $('#overlay input:not([type=checkbox]):not([type=radio]), #overlay textarea');
    if (first && !wide) first.focus();
  }
  const closeDialog = () => { $('#overlay').innerHTML = ''; };
  const dialogOpen = () => Boolean($('#overlay')?.firstElementChild);

  function sessionDialog() {
    const s = S.session || {};
    if (OFFLINE) {
      openDialog('Session', `<dl class="kv">${['name', 'client', 'action', 'notes'].map((k) => `<dt>${k}</dt><dd>${esc(s[k] || '—')}</dd>`).join('')}
        <dt>synthetic</dt><dd>${s.sample ? 'yes' : 'no'}</dd><dt>redacted</dt><dd>${ARCHIVE.redacted ? 'yes' : 'no'}</dd></dl>`);
      return;
    }
    openDialog('Session', `
      <label for="sName">Name</label><input id="sName" value="${esc(s.name)}">
      <div class="row">
        <div><label for="sClient">Client</label><input id="sClient" value="${esc(s.client)}" placeholder="e.g. Claude Code on Windows 11, Codex CLI, Chrome"></div>
        <div><label for="sAction">Action</label><input id="sAction" value="${esc(s.action)}" placeholder="e.g. attach a 2 MB PDF and ask one question"></div>
      </div>
      <label for="sNotes">Notes</label><textarea id="sNotes" placeholder="Versions, settings, what you expected">${esc(s.notes)}</textarea>
      <h3>Start over</h3>
      <p>Replacing the session requires the proxy and capture to be stopped. Export first if you want to keep the current records.</p>
      <div style="display:flex;gap:8px"><button class="danger" data-action="session-new">New empty session</button><button data-action="sample">Load synthetic sample</button></div>`,
    '<button data-action="dialog-close">Cancel</button><button class="primary" data-action="session-save">Save</button>');
  }

  function exportDialog() {
    const selection = S.compare.length ? S.compare : S.selected?.kind === 'flow' ? [S.selected.id] : [];
    openDialog('Export', `
      <h3 style="margin-top:0">Session archive</h3>
      <p>Everything recorded — headers, captured bodies, packets, notes — as a .wscope file WireScope can import again. It contains credentials if the traffic did.</p>
      <button data-action="export-session">Download .wscope</button>
      <h3>Packets</h3>
      <p>${esc(S.stats.packets || 0)} packets as pcapng, readable by Wireshark and tcpdump.</p>
      <button data-action="export-pcap" ${S.stats.packets ? '' : 'disabled'}>Download .pcapng</button>
      <h3>Standalone HTML report</h3>
      <p>One file containing this viewer and the data. Opens in a browser without WireScope or network access.</p>
      <label class="checkbox-label"><input type="checkbox" id="reportRedact" checked> Redact: drop bodies, packets, query strings, and authorization / cookie / API-key / upload-URL header values</label>
      <label class="checkbox-label"><input type="radio" name="reportScope" value="all" checked> All ${S.flows.length} requests</label>
      <label class="checkbox-label"><input type="radio" name="reportScope" value="selected" ${selection.length ? '' : 'disabled'}> Selected only ${selection.length ? selection.map((i) => `#${i}`).join(', ') : '(select or tick requests first)'} — packets are left out</label>
      <p class="small">Redaction is pattern-based. Paths, other headers, notes and session text are kept; read the report before sharing it.</p>
      <button class="primary" data-action="export-report" data-ids="${selection.join(',')}">Download report</button>`);
  }

  async function caDialog() {
    const ca = await api('GET', '/api/ca');
    const port = S.proxy.port || Number($('#proxyPort')?.value) || 18080;
    const path = ca.path || '<path to root-ca.pem>';
    const setup = [
      '# curl',
      `curl -x http://127.0.0.1:${port} --cacert "${path}" https://example.com/`,
      '',
      '# PowerShell, current window: tools that honour proxy variables',
      `$env:HTTPS_PROXY = "http://127.0.0.1:${port}"`,
      `$env:HTTP_PROXY  = "http://127.0.0.1:${port}"`,
      '# Node.js-based CLIs also need the CA',
      `$env:NODE_EXTRA_CA_CERTS = "${path}"`,
      '# Python requests / httpx',
      `$env:REQUESTS_CA_BUNDLE = "${path}"`,
      `$env:SSL_CERT_FILE = "${path}"`,
    ].join('\n');
    openDialog('Certificate and client setup', `
      <dl class="kv">
        <dt>Local CA</dt><dd>${ca.exists ? 'created' : 'not created yet (starting the proxy creates it)'}</dd>
        ${ca.exists ? `<dt>Subject</dt><dd>${esc(ca.subject)}</dd><dt>File</dt><dd>${esc(ca.path)}</dd><dt>${esc(ca.fingerprintType || 'Fingerprint')}</dt><dd>${esc(ca.fingerprint)}</dd>` : ''}
      </dl>
      <div style="display:flex;gap:8px;margin-top:14px">
        ${ca.exists ? '' : '<button class="primary" data-action="ca-create">Create local CA</button>'}
        <button data-action="ca-download" ${ca.exists ? '' : 'disabled'}>Download PEM</button>
      </div>
      <h3>Trust on Windows</h3>
      <p>Adds the CA to the current user's Trusted Root store so browsers and most Windows apps accept the proxy's certificates. Remove it when you are done.</p>
      <div style="display:flex;gap:8px"><button data-action="ca-trust" data-install="1" ${ca.exists ? '' : 'disabled'}>Install for current user</button><button class="danger" data-action="ca-trust" data-install="0" ${ca.exists ? '' : 'disabled'}>Remove</button></div>
      <h3>Client setup</h3>
      <p>WireScope changes the Windows system proxy only when you press <b>Use as system proxy</b>, and restores the saved setting when you turn it off, stop the proxy or exit. Browsers and apps that read the system setting follow it; curl and Node.js-based CLIs do not, so point those at the proxy with the variables below. Clients that pin certificates will fail the TLS handshake instead of showing up in plaintext.</p>
      <pre class="code">${esc(setup)}</pre>`);
    S.ca = ca;
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  async function proxyToggle() {
    if (S.proxy.running) S.proxy = await api('POST', '/api/proxy/stop', {});
    else {
      const port = Number($('#proxyPort').value) || 18080;
      S.proxy = await api('POST', '/api/proxy/start', { port, mitm: $('#proxyMitm').checked });
      toast(`Proxy listening on 127.0.0.1:${S.proxy.port}`);
    }
    updateToolbar(); renderTable();
  }

  async function captureToggle() {
    if (S.capture.running) S.capture = await api('POST', '/api/capture/stop', {});
    else {
      const device = $('#captureDevice').value;
      if (!device) throw new Error('Select a capture interface');
      S.capture = await api('POST', '/api/capture/start', { device, filter: $('#captureFilter').value.trim() });
    }
    updateToolbar();
  }

  async function replaced(message) {
    resetSelection();
    closeDialog();
    S.revision = 0;
    await refreshNow();
    renderAll();
    if (message) toast(message);
  }

  async function importFile(file) {
    const buf = await file.arrayBuffer();
    const head = new Uint8Array(buf, 0, Math.min(64, buf.byteLength));
    let i = 0;
    while (i < head.length && (head[i] === 0x20 || head[i] === 0x0a || head[i] === 0x0d || head[i] === 0x09)) i++;
    if (head[i] === 0x7b) {
      await api('POST', '/api/session/import', new TextDecoder().decode(buf));
      await replaced(`Imported session from ${file.name}`);
    } else {
      const r = await api('POST', '/api/pcap/import', buf);
      S.view = 'packets'; S.category = 'all';
      await replaced(`Imported ${r.packets} packets from ${file.name}`);
    }
  }

  function openPacket(id, fromFlow) {
    const p = S.packetById.get(id) || offline?.packets.get(id);
    if (fromFlow) S.backTo = fromFlow;
    if (S.view !== 'packets') { S.view = 'packets'; S.category = 'all'; renderCenter(); }
    if (p?.key) S.connection = p.key;
    renderSidebar(); renderTable();
    return select('packet', id);
  }

  const ACTIONS = {
    category: (el) => setView(el.dataset.view, el.dataset.cat),
    'trace-rerun': () => runAnalysis(true),
    'files-add': () => $('#addFiles').click(),
    'folder-add': () => $('#addFolder').click(),
    'file-remove': async (el) => { await api('DELETE', `/api/files/${el.dataset.id}`); await refreshNow(); runAnalysis(true); },
    'trace-file': (el) => {
      const id = Number(el.dataset.id);
      S.trace.fileFilter = S.trace.fileFilter === id ? null : id;
      if (S.view !== 'trace') setView('trace'); else { renderSidebar(); renderTraceTable(); }
    },
    'trace-case': (el) => { S.trace.caseSensitive = el.checked; runSearch(); renderTraceTable(); renderSidebar(); },
    'trace-hit': (el) => selectTrace('hit', Number(el.dataset.i)),
    'trace-match': (el) => selectTrace('match', Number(el.dataset.i)),
    'trace-canary': (el) => selectTrace('canary', Number(el.dataset.i)),
    'trace-open-flow': (el) => {
      S.flowTab = el.dataset.side === 'response' ? 'response' : 'request';
      S.view = 'flows'; S.category = 'all'; S.connection = '';
      renderSidebar(); renderCenter(); renderTable();
      return select('flow', Number(el.dataset.id));
    },
    'trace-open-packets': (el) => {
      S.flowTab = 'packets';
      S.view = 'flows'; S.category = 'all'; S.connection = '';
      renderSidebar(); renderCenter(); renderTable();
      return select('flow', Number(el.dataset.id));
    },
    connection: (el) => { S.connection = S.connection === el.dataset.key ? '' : el.dataset.key; renderSidebar(); renderTable(); },
    'clear-connection': () => { S.connection = ''; renderSidebar(); renderTable(); },
    process: (el) => { const pid = Number(el.dataset.pid); S.processPid = S.processPid === pid ? null : pid; renderSidebar(); renderTable(); },
    'clear-process': () => { S.processPid = null; renderSidebar(); renderTable(); },
    'clear-filters': () => { S.search[S.view] = ''; S.stateFilter = ''; S.connection = ''; S.processPid = null; S.category = 'all'; renderSidebar(); renderCenter(); renderTable(); },
    'select-flow': (el) => { S.backTo = null; return select('flow', Number(el.dataset.id)); },
    'select-packet-row': (el) => select('packet', Number(el.dataset.id)),
    'open-packet': (el) => openPacket(Number(el.dataset.id), S.selected?.kind === 'flow' ? S.selected.id : S.backTo),
    'back-to-flow': () => {
      const id = S.backTo;
      S.backTo = null;
      S.view = 'flows'; S.category = 'all'; S.connection = '';
      renderSidebar(); renderCenter(); renderTable();
      return select('flow', id);
    },
    'stream-key': (el) => {
      const key = el.dataset.key;
      const all = OFFLINE ? [...offline.packets.values()] : S.packets;
      const first = all.find((p) => p.key === key && p.seq !== undefined);
      if (!first) throw new Error('No TCP packets for these endpoints');
      S.packetTab = 'stream';
      return openPacket(first.id, S.selected?.kind === 'flow' ? S.selected.id : S.backTo);
    },
    'compare-toggle': (el) => {
      const id = Number(el.dataset.id);
      if (el.checked) { S.compare = [...S.compare.filter((x) => x !== id), id].slice(-2); }
      else S.compare = S.compare.filter((x) => x !== id);
      for (const box of $$('#tableWrap input[data-action="compare-toggle"]')) box.checked = S.compare.includes(Number(box.dataset.id));
      renderCompareTray();
    },
    'compare-clear': () => { S.compare = []; renderTable(); },
    'compare-open': openCompare,
    tab: (el) => {
      if (S.selected?.kind === 'flow') S.flowTab = el.dataset.tab; else S.packetTab = el.dataset.tab;
      renderInspector();
    },
    'body-mode': (el) => { S.bodyMode[`${S.detail.id}:${el.dataset.side}`] = el.dataset.mode; renderInspector(true); },
    'decode-toggle': (el) => { S.decodeOff[`${S.detail.id}:${el.dataset.side}`] = !el.checked; renderInspector(true); },
    'body-download': (el) => {
      const f = S.detail, side = el.dataset.side, msg = f[side] || {};
      const ct = headerValue(msg.headers, 'content-type');
      const ext = /json/.test(ct) ? '.json' : /event-stream|text\//.test(ct) ? '.txt' : '.bin';
      download(`wirescope-${f.id}-${side}${contentEncoding(msg.headers) ? `.${contentEncoding(msg.headers)}` : ''}${ext}`, bodyBytes(msg.body));
    },
    'hex-more': (el) => { S.hexLimit[el.dataset.key] = (S.hexLimit[el.dataset.key] || HEX_PAGE) + HEX_PAGE * 4; renderInspector(true); },
    field: (el) => {
      S.highlight = { offset: Number(el.dataset.off), length: Number(el.dataset.len) };
      applyHighlight(S.highlight);
      hexSpans[S.highlight.offset]?.scrollIntoView({ block: 'nearest' });
    },
    'packet-download': () => download(`wirescope-packet-${S.detail.id}.bin`, bodyBytes(S.detail)),
    'stream-mode': (el) => { S.streamMode = el.dataset.mode; renderInspector(true); },
    'notes-save': async () => {
      const id = S.detail.id;
      await api('POST', `/api/flows/${id}/notes`, { notes: $('#notesText').value });
      toast(`Notes saved for #${id}`);
      await refreshNow();
    },
    'proxy-toggle': proxyToggle,
    'sysproxy-toggle': async () => {
      const on = !S.systemProxy.ownedByWireScope;
      S.systemProxy = await api('POST', '/api/sysproxy', { enable: on });
      toast(on ? `System proxy → ${S.systemProxy.current?.server}` : 'System proxy restored');
      updateToolbar();
    },
    'sysproxy-restore': async () => {
      S.systemProxy = await api('POST', '/api/sysproxy', { enable: false });
      toast('System proxy restored from the saved backup');
      updateToolbar();
    },
    'capture-toggle': captureToggle,
    session: sessionDialog,
    'session-save': async () => {
      await api('POST', '/api/session', { name: $('#sName').value, client: $('#sClient').value, action: $('#sAction').value, notes: $('#sNotes').value });
      closeDialog();
      await refreshNow();
      toast('Session details saved');
    },
    'session-new': async () => {
      await api('POST', '/api/session/new', { name: `Capture ${stamp()}` });
      await replaced('New empty session');
    },
    sample: async () => {
      await api('POST', '/api/sample', {});
      S.view = 'flows'; S.category = 'all';
      await replaced('Loaded the synthetic sample (.example hosts, not real traffic)');
    },
    import: () => $('#importFile').click(),
    export: exportDialog,
    'export-session': async () => download(`${safeName(S.session.name)}-${stamp()}.wscope`, await api('GET', '/api/session/download', undefined, 'blob')),
    'export-pcap': async () => download(`${safeName(S.session.name)}-${stamp()}.pcapng`, await api('GET', '/api/pcap/download', undefined, 'blob')),
    'export-report': async (el) => {
      const scope = $('input[name="reportScope"]:checked')?.value;
      const ids = scope === 'selected' ? el.dataset.ids.split(',').filter(Boolean).map(Number) : [];
      const redact = $('#reportRedact').checked;
      const html = await api('POST', '/api/report', { redact, ids }, 'blob');
      download(`${safeName(S.session.name)}-${redact ? 'redacted-' : ''}report-${stamp()}.html`, html);
    },
    ca: caDialog,
    'ca-create': async () => { await api('POST', '/api/ca/create', {}); await caDialog(); toast('Local CA created'); },
    'ca-download': () => download('wirescope-root-ca.pem', S.ca?.pem || '', 'application/x-pem-file'),
    'ca-trust': async (el) => {
      const install = el.dataset.install === '1';
      await api('POST', '/api/ca/trust', { install });
      toast(install ? 'CA installed in the current user Trusted Root store' : 'CA removed from the current user Trusted Root store');
    },
    'dialog-close': closeDialog,
    overlay: closeDialog,
    'cmp-part': (el) => { S.cmp.part = el.dataset.part; renderCompare(); },
    'cmp-view': (el) => { S.cmp.view = el.dataset.view; renderCompare(); },
    'cmp-sort': (el) => { S.cmp.sortKeys = el.checked; $('#cmpContent').innerHTML = compareContent(); },
    'cmp-same': (el) => { S.cmp.showSame = el.checked; $('#cmpContent').innerHTML = compareContent(); },
  };
  const LIVE_ONLY = new Set(['proxy-toggle', 'sysproxy-toggle', 'sysproxy-restore', 'capture-toggle', 'session-save', 'session-new', 'sample', 'import', 'export',
    'export-session', 'export-pcap', 'export-report', 'ca', 'ca-create', 'ca-download', 'ca-trust', 'notes-save']);

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  function bindEvents() {
    document.addEventListener('click', async (e) => {
      // Clicking a byte selects the narrowest field that covers it.
      const byte = e.target.closest?.('#packetHex .hex-byte[data-off]');
      if (byte) {
        const off = Number(byte.dataset.off);
        const rows = $$('#inspector .field-row').map((r) => ({ r, o: Number(r.dataset.off), n: Number(r.dataset.len) }))
          .filter((x) => off >= x.o && off < x.o + x.n).sort((a, b) => a.n - b.n);
        S.highlight = rows.length ? { offset: rows[0].o, length: rows[0].n } : { offset: off, length: 1 };
        applyHighlight(S.highlight);
        rows[0]?.r.scrollIntoView({ block: 'nearest' });
        return;
      }
      const el = e.target.closest?.('[data-action]');
      if (!el) return;
      const action = el.dataset.action;
      if (action === 'overlay' && e.target !== el) return;
      const handler = ACTIONS[action];
      if (!handler || (OFFLINE && LIVE_ONLY.has(action))) return;
      if (el.tagName === 'A') e.preventDefault();
      const busy = el.tagName === 'BUTTON';
      if (busy) el.classList.add('busy');
      try { await handler(el, e); } catch (err) { toast(err.message || String(err), true); } finally { if (busy) el.classList.remove('busy'); }
    });

    const filterLater = debounce(() => renderTable(), 120);
    const ignoreLater = debounce(() => { const c = $('#cmpContent'); if (c) c.innerHTML = compareContent(); }, 250);
    const searchLater = debounce(() => { runSearch(); renderTraceTable(); renderSidebar(); }, 250);
    document.addEventListener('input', (e) => {
      const t = e.target;
      if (t.id === 'traceQuery') { S.trace.query = t.value; searchLater(); return; }
      if (t.id === 'search') { S.search[S.view] = t.value; filterLater(); }
      else if (t.id === 'cmpIgnore') { S.cmp.ignore = t.value; ignoreLater(); }
      else if (t.dataset?.input === 'sse-join') {
        S.sseJoin[t.dataset.key] = t.value;
        const f = S.detail, side = t.dataset.key.split(':')[1];
        const body = f[side].body;
        const bytes = decoded.has(body) && !S.decodeOff[t.dataset.key] ? decoded.get(body).bytes : bodyBytes(body);
        $('#sseJoined').innerHTML = sseJoined(parseSse(decodeText(bytes)), t.value.trim());
      }
    });
    document.addEventListener('change', async (e) => {
      const t = e.target;
      if (t.id === 'stateFilter') { S.stateFilter = t.value; renderTable(); }
      else if (t.id === 'captureDevice') t.title = t.value;
      else if ((t.id === 'addFiles' || t.id === 'addFolder') && t.files?.length) {
        const files = [...t.files];
        t.value = '';
        try { await addLocalFiles(files); } catch (err) { toast(`Adding files failed: ${err.message}`, true); }
      }
      else if (t.id === 'importFile' && t.files?.[0]) {
        const file = t.files[0];
        t.value = '';
        try { await importFile(file); } catch (err) { toast(`Import failed: ${err.message}`, true); }
      }
    });

    document.addEventListener('mouseover', (e) => {
      const row = e.target.closest?.('.field-row');
      if (row) applyHighlight({ offset: Number(row.dataset.off), length: Number(row.dataset.len) });
    });
    document.addEventListener('mouseout', (e) => {
      const row = e.target.closest?.('.field-row');
      if (row && !row.contains(e.relatedTarget)) applyHighlight(S.highlight);
    });
    document.addEventListener('focusout', () => {
      setTimeout(() => { if (S.inspectorStale && !editingInInspector()) renderInspector(true); }, 0);
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && dialogOpen()) { closeDialog(); return; }
      if (dialogOpen() || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '')) return;
      if (e.key === '/') { e.preventDefault(); $('#search')?.focus(); return; }
      const down = e.key === 'ArrowDown' || e.key === 'j', up = e.key === 'ArrowUp' || e.key === 'k';
      if (!down && !up) return;
      const ids = S.visibleIds;
      if (!ids.length) return;
      e.preventDefault();
      if (isTraceView()) { moveTraceSelection(down ? 1 : -1); return; }
      const kind = S.view === 'flows' ? 'flow' : 'packet';
      const current = S.selected?.kind === kind ? ids.indexOf(S.selected.id) : -1;
      const next = current < 0 ? (down ? 0 : ids.length - 1) : Math.max(0, Math.min(ids.length - 1, current + (down ? 1 : -1)));
      if (S.view === 'flows') S.backTo = null;
      select(kind, ids[next]);
    });
  }

  // ---------------------------------------------------------------------------
  // Start
  // ---------------------------------------------------------------------------

  async function start() {
    renderShell();
    bindEvents();
    if (OFFLINE) {
      S.session = ARCHIVE.session || {};
      S.bodyLimit = ARCHIVE.bodyLimit || S.bodyLimit;
      S.flows = ARCHIVE.flows || [];
      S.packets = ARCHIVE.packets || [];
      S.stats = { flows: S.flows.length, packets: S.packets.length };
      S.localFiles = (ARCHIVE.localFiles || []).map(({ base64, ...meta }) => meta);
      indexRecords();
      document.title = `${S.session.name || 'Capture'} · WireScope report`;
      renderAll();
      return;
    }
    try {
      const res = await fetch('/api/bootstrap', { cache: 'no-store' });
      const boot = await res.json();
      S.token = boot.token; S.bodyLimit = boot.bodyLimit || S.bodyLimit; S.version = boot.version; S.uiPort = boot.uiPort;
    } catch (e) {
      document.getElementById('app').innerHTML = `<div class="empty"><strong>Cannot reach the WireScope engine</strong><p>${esc(e.message)}</p></div>`;
      return;
    }
    renderAll();
    $('#captureFilter').value = `not tcp port ${S.uiPort}`;
    loadInterfaces();
    poll();
  }

  start();
})();
