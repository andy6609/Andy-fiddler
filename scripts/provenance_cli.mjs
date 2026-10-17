#!/usr/bin/env node
// Trace local files into a recorded WireScope session, from the terminal.
//
//   node scripts/provenance_cli.mjs session.wscope                 use the snapshots stored in the session
//   node scripts/provenance_cli.mjs session.wscope --files ./repo  snapshot a directory now instead
//   node scripts/provenance_cli.mjs session.wscope --json          machine-readable output (no body views)
//
// Same code as the inspector (web/provenance.js). Output is the raw result: which file ranges appeared in which
// request, which canaries were seen or not, and what could not be searched. No conclusions are printed.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
// createRequire resolves a relative path against this file's URL. Building the path from URL.pathname breaks on
// Windows ("/D:/a/..." is not a path there), which only the Windows CI run caught.
const P = require('../web/provenance.js');

const args = process.argv.slice(2);
const sessionPath = args.find((a) => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--files');
if (!sessionPath) {
  console.error('usage: provenance_cli.mjs session.wscope [--files DIR] [--json]');
  process.exit(2);
}
const filesDir = args.includes('--files') ? args[args.indexOf('--files') + 1] : null;
const asJson = args.includes('--json');

// Same rules as the inspector's folder picker: skip .git and node_modules, 2 MiB per file.
function snapshotDir(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && fs.statSync(full).size <= 2 * 1024 * 1024) {
        out.push({ id: out.length + 1, name: path.relative(dir, full).split(path.sep).join('/'), base64: fs.readFileSync(full).toString('base64') });
      }
    }
  };
  walk(dir);
  return out;
}

const archive = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
const localFiles = filesDir ? snapshotDir(filesDir) : archive.localFiles || [];
const r = await P.analyze(archive, { localFiles });

if (asJson) {
  const { views, ...rest } = r;
  console.log(JSON.stringify(rest, null, 2));
  process.exit(0);
}

const flowById = new Map((archive.flows || []).map((f) => [f.id, f]));
const where = (x) => {
  const f = flowById.get(x.flowId);
  return `#${x.flowId} ${x.side === 'request' ? '→' : '←'} ${f ? `${f.method} ${f.host}${f.path}` : ''}`.trim();
};
const part = (m) => (m.kind === 'bytes' ? (m.whole ? 'whole file' : `first ${m.bytes} bytes`) : m.fileFrom === m.fileTo ? `line ${m.fileFrom}` : `lines ${m.fileFrom}-${m.fileTo}`);

console.log(`session: ${archive.session?.name || '?'} · ${(archive.flows || []).length} requests · ${r.viewCount} body views · ${r.files.length} local files${filesDir ? ` (from ${filesDir})` : ''}`);
console.log('\nCOVERAGE');
for (const c of r.coverage) {
  const seen = c.binary ? `${c.matchedBytes}/${c.size} bytes` : `${c.matchedAnchors}/${c.anchorLines} lines`;
  const ranges = c.binary ? '' : c.ranges.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',');
  console.log(`  ${c.fileName.padEnd(36)} ${seen.padEnd(16)} ${ranges}`);
}
console.log('\nMATCHES');
if (!r.matches.length) console.log('  none');
for (const m of r.matches) console.log(`  ${m.fileName} ${part(m)}  ->  ${where(m)}  at ${m.locator}  [${m.transforms.join(' ') || 'as captured'}]`);
console.log('\nCANARIES');
for (const x of r.canaries.sightings) console.log(`  seen      ${x.token}  from ${x.from.map((f) => `${f.fileName}${f.line ? `:${f.line}` : ''}`).join(', ') || '(no local file)'}  in ${where(x)} at ${x.locator}${x.count > 1 ? `  (${x.count}×)` : ''}`);
for (const x of r.canaries.notSeen) console.log(`  not seen  ${x.token}  from ${x.from.map((f) => `${f.fileName}${f.line ? `:${f.line}` : ''}`).join(', ')}`);
if (!r.canaries.sightings.length && !r.canaries.notSeen.length) console.log('  none planted');
console.log('\nNOT SEARCHED');
if (r.bodyLimit) console.log(`  bytes past the ${r.bodyLimit}-byte capture limit of each body`);
for (const n of r.notes) console.log(`  #${n.flowId} ${n.side}: ${n.note}`);
