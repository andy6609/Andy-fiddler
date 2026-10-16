#!/usr/bin/env python3
"""Turn a build or test log into GitHub Actions annotations.

Annotations show on the run page and through the public check-runs API, so the evidence (compiler
diagnostics, per-test ok/FAIL counts, failing check lines) stays readable without downloading logs.

    python .github/ci_annotate.py build build.log
    python .github/ci_annotate.py test ctest.log
"""
import os
import re
import sys

sys.dont_write_bytecode = True
# The Windows runner's Python writes cp1252 by default; test output contains Korean, which would crash this script mid-way
# (that silently dropped the "test #N output" annotations in earlier runs).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# MSVC / MSBuild:  C:\src\proxy.cpp(12,5): warning C4244: '=': conversion ... [C:\build\WireScope.vcxproj]
#                  proxy.obj : error LNK2019: unresolved external symbol ...
DIAG = re.compile(r"^\s*(?:\d+>)?(?P<file>.+?)(?:\((?P<line>\d+)(?:,\d+)?\))?\s*:\s+(?:fatal\s+)?(?P<kind>error|warning)\s+"
                  r"(?P<code>[A-Z]+\d+)\s*:\s*(?P<msg>.*?)(?:\s+\[[^\]]*\])?\s*$")


WORKSPACE = os.environ.get("GITHUB_WORKSPACE", "").replace("\\", "/").rstrip("/")


def escape(text):
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def emit(kind, title, lines, limit=80):
    shown = [line if len(line) <= 400 else line[:400] + " ..." for line in lines[:limit]]
    if len(lines) > limit:
        shown.append(f"... {len(lines) - limit} more")
    print(f"::{kind} title={title.replace(',', '%2C').replace(':', '%3A')}::{escape(chr(10).join(shown))}")


def build(log):
    seen, errors, warnings = set(), [], []
    for raw in log:
        m = DIAG.match(raw)
        if not m:
            continue
        where = m["file"].strip().replace("\\", "/")
        if WORKSPACE and where.lower().startswith(WORKSPACE.lower() + "/"):
            where = where[len(WORKSPACE) + 1:]
        line = f"{where}{':' + m['line'] if m['line'] else ''}  {m['code']}  {m['msg']}"
        if line in seen:
            continue  # MSBuild repeats diagnostics in its summary
        seen.add(line)
        (errors if m["kind"] == "error" else warnings).append(line)
    codes = {}
    for w in warnings:
        code = w.split()[1]
        codes[code] = codes.get(code, 0) + 1
    if errors:
        emit("error", f"MSVC errors ({len(errors)})", errors)
    if warnings:
        emit("warning", f"MSVC warnings ({len(warnings)}: " + ", ".join(f"{c}x{n}" for c, n in sorted(codes.items())) + ")", warnings)
    if not errors and not warnings:
        emit("notice", "MSVC build", ["0 errors, 0 warnings"])


def test(log):
    # ctest -V prefixes each line a test prints with "<test number>: ". The Python tests print
    # "  ok   <label>" / "  FAIL <label>"; core_tests prints "<n> checks, <m> failures".
    per, fails, summary = {}, [], []
    for raw in log:
        m = re.match(r"^\s*\d+/\d+ Test\s+#(\d+): (\S+) \.+\s*(.*)$", raw)
        if m:
            summary.append(f"#{m[1]} {m[2]}: {' '.join(m[3].split())}")
            continue
        if "tests passed" in raw or "tests failed" in raw:
            summary.append(raw.strip())
            continue
        m = re.match(r"^(\d+): (.*)$", raw)
        if not m:
            continue
        c = per.setdefault(m[1], {"ok": 0, "fail": 0, "lines": [], "checks": "", "info": []})
        text = m[2]
        if text.startswith("  ok "):
            c["ok"] += 1
        elif text.startswith("  FAIL"):
            c["fail"] += 1
            fails.append(text.strip())
        elif text.startswith("  info "):
            c["info"].append(text.strip()[5:])  # raw values the tests print (PIDs, registry values, recorded errors)
        elif re.match(r"^\d+ checks, \d+ failures", text):
            c["checks"] = text.strip()
        c["lines"].append(text)
    counts = [f"#{n}: " + (c["checks"] or f"{c['ok']} ok, {c['fail']} FAIL") for n, c in sorted(per.items(), key=lambda x: int(x[0]))]
    emit("notice", "ctest", summary + counts)
    for n, c in sorted(per.items(), key=lambda x: int(x[0])):
        if c["info"]:
            emit("notice", f"test #{n} info", c["info"], limit=30)
    if fails:
        emit("error", f"Failing checks ({len(fails)})", fails)
    for n, c in per.items():
        if c["fail"] or any("Traceback" in line or line.startswith("FAIL") for line in c["lines"]):
            emit("error", f"test #{n} output (last 60 lines)", c["lines"][-60:], limit=60)


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    build(lines) if mode == "build" else test(lines)
