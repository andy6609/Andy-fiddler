#!/usr/bin/env node
// Compare experiment-001 runs side by side, requests only (what left the machine).
//
//   node experiments/001-agent-file-egress/compare_runs.mjs results/001-a results/001-b ... [--json]
//
// Per registered file and run: meaningful lines seen in requests / all meaningful lines, then
//   C  its canary was seen in a request
//   N  its path or name was in a request (an ls listing, a prompt, a tool argument)
// A model's reply quoting a file is a response and is not counted here; the inspector and provenance_cli.mjs show both.
// Same judging code as the inspector (web/provenance.js). Header values are never printed.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const P = require('../../web/provenance.js');

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const dirs = args.filter((a) => a !== '--json');
if (!dirs.length) {
  console.error('usage: node compare_runs.mjs RESULT_DIR... [--json]');
  process.exit(2);
}

const MODEL_PATH = /\/v1\/messages|\/codex\/responses|\/v1\/responses|\/v1\/chat\/completions/;
const runs = [];
for (const dir of dirs) {
  const archive = JSON.parse(fs.readFileSync(path.join(dir, 'session.wscope'), 'utf8'));
  const meta = fs.existsSync(path.join(dir, 'run.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8')) : {};
  const r = await P.analyze(archive);
  const files = P.prepareFiles(archive.localFiles);
  const sent = r.matches.filter((m) => m.side === 'request');
  const perFile = {};
  for (const f of files) {
    const lines = f.binary ? null : P.coverage(f, sent);
    const bytes = f.binary ? sent.filter((m) => m.fileId === f.id).reduce((n, m) => Math.max(n, m.bytes || 0), 0) : 0;
    perFile[f.name] = {
      lines: lines ? { seen: lines.matchedAnchors, of: lines.anchorLines, ranges: lines.ranges } : null,
      bytes: f.binary ? { seen: bytes, of: f.size } : null,
      canary: r.canaries.sightings.some((x) => x.side === 'request' && x.from.some((y) => y.fileId === f.id)),
      name: r.names.some((n) => n.fileId === f.id),
      requests: [...new Set([...sent.filter((m) => m.fileId === f.id).map((m) => m.flowId), ...r.canaries.sightings.filter((x) => x.side === 'request' && x.from.some((y) => y.fileId === f.id)).map((x) => x.flowId)])],
    };
  }
  const flows = (archive.flows || []).filter((f) => f.method !== 'CONNECT');
  const model = flows.filter((f) => MODEL_PATH.test(f.path || ''));
  // one WebSocket connection carries many turns: count its client messages, and one per HTTP request
  const messages = model.reduce((n, f) => n + (f.protocol === 'WebSocket'
    ? P.wsMessages(P.wsFrames(P.b64ToBytes(f.request?.body?.base64 || '')).frames).messages.length : 1), 0);
  runs.push({
    dir: path.basename(dir), label: meta.label || archive.session?.client || '', task: meta.task || archive.session?.action || '',
    seconds: meta.seconds, exit: meta.exit, requests: flows.length, hosts: [...new Set(flows.map((f) => f.host))],
    modelRequests: model.length, modelMessages: messages, modelBytesSent: model.reduce((n, f) => n + (f.request?.body?.total || 0), 0),
    perFile, unknownCanaries: r.canaries.unknown, notes: r.notes.length,
  });
}

if (asJson) {
  console.log(JSON.stringify(runs, null, 2));
  process.exit(0);
}

const names = [...new Set(runs.flatMap((r) => Object.keys(r.perFile)))];
const width = Math.max(14, ...runs.map((r) => r.dir.length + 2));
const pad = (s, n) => String(s).padEnd(n);
const cell = (x) => {
  if (!x) return '';
  const part = x.lines ? `${x.lines.seen}/${x.lines.of}` : x.bytes.seen ? `${x.bytes.seen}/${x.bytes.of}B` : `-`;
  const flags = `${x.canary ? 'C' : ''}${x.name ? 'N' : ''}`;
  return flags ? `${part} ${flags}` : part;
};
for (const r of runs) console.log(`${r.dir}: ${r.label} · "${r.task}" · exit ${r.exit} · ${r.seconds}s`);
console.log('');
console.log(pad('file (requests only)', 24) + runs.map((r) => pad(r.dir, width)).join(''));
for (const n of names) console.log(pad(n, 24) + runs.map((r) => pad(cell(r.perFile[n]), width)).join(''));
console.log('');
for (const [k, label] of [['requests', 'requests (all)'], ['modelRequests', 'model requests'], ['modelMessages', 'model messages sent'], ['modelBytesSent', 'model bytes sent*'], ['notes', 'not-searched notes']]) {
  console.log(pad(label, 24) + runs.map((r) => pad(r[k], width)).join(''));
}
console.log(pad('hosts', 24) + runs.map((r) => pad(r.hosts.length, width)).join(''));
console.log('\nlines: meaningful lines (not blank, not just brackets) seen in a request / all; C canary seen; N path or name seen');
console.log('* bytes on the wire: WebSocket messages with permessage-deflate are counted compressed, HTTP bodies as sent');
console.log('Not seen means not seen in the captured requests; see each run\'s summary.txt for what was not searched.');
