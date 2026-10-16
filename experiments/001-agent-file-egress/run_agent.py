#!/usr/bin/env python3
"""Run one coding agent inside the sandbox with WireScope recording, then save everything.

    python3 run_agent.py --sandbox /tmp/egress-sandbox --label "claude-code 2.1" --out results/claude-code \\
        --task "change the timeout in src/config.ts to 30 s" -- claude -p "{task}"

What it does:
  1. starts the WireScope engine (body limit 8 MiB) and its proxy with TLS termination
  2. records the label and task as session metadata, registers every sandbox file as a local file snapshot
  3. runs the command in the sandbox; only that process gets the proxy and CA variables
  4. saves session.wscope, report.html (unredacted: it is your own experiment), summary.txt and run.json

The proxy and CA variables are set for the agent process only. Nothing system-wide changes.
"""
import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
EXE = ".exe" if os.name == "nt" else ""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Engine:
    def __init__(self, build, data, body_limit, log):
        self.port = free_port()
        self.proc = subprocess.Popen([os.path.join(build, f"WireScope{EXE}"), "--no-open", "--port", str(self.port), "--data", data,
                                      "--web", os.path.join(build, "web"), "--body-limit", str(body_limit)], stdout=log, stderr=subprocess.STDOUT)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(100):
            try:
                self.token = json.load(urllib.request.urlopen(self.base + "/api/bootstrap"))["token"]
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("engine did not start; see engine.log")

    def call(self, method, path, body=None, raw=False):
        headers = {"X-WireScope-Token": self.token}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req) as r:
            out = r.read()
        return out if raw else json.loads(out)


def sandbox_files(root):
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        for n in names:
            if n == ".wirescope-sandbox":
                continue
            full = os.path.join(d, n)
            if os.path.getsize(full) <= 2 * 1024 * 1024:
                yield os.path.relpath(full, root).replace(os.sep, "/"), full


def hosts_section(archive):
    rows = defaultdict(lambda: [0, 0, 0])
    for f in archive["flows"]:
        r = rows[f"{f.get('method', '')} {f.get('host', '')}"] if f.get("method") == "CONNECT" else rows[f.get("host", "")]
        r[0] += 1
        r[1] += f["request"]["body"]["total"]
        r[2] += f["response"]["body"]["total"]
    lines = ["HOSTS (requests, bytes sent, bytes received)"]
    for host, (n, up, down) in sorted(rows.items(), key=lambda x: -x[1][0]):
        lines.append(f"  {host:48} {n:5} {up:12} {down:12}")
    if not archive["flows"]:
        lines.append("  no requests were recorded: the client may not use HTTPS_PROXY, or it failed before sending anything")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandbox", required=True)
    ap.add_argument("--label", required=True, help="agent name and version, stored in the session")
    ap.add_argument("--task", required=True, help="the task given to the agent; replaces {task} in the command")
    ap.add_argument("--out", required=True)
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("--body-limit", type=float, default=8, help="MiB captured per body direction (default 8)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- then the agent command")
    a = ap.parse_args()
    command = [x.replace("{task}", a.task) for x in (a.command[1:] if a.command[:1] == ["--"] else a.command)]
    if not command:
        ap.error("give the agent command after --")
    sandbox = os.path.abspath(a.sandbox)
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)

    with open(os.path.join(out, "engine.log"), "wb") as log:
        engine = Engine(a.build, os.path.join(out, "engine-data"), a.body_limit, log)
        try:
            proxy = free_port()
            engine.call("POST", "/api/proxy/start", {"port": proxy, "mitm": True})
            ca = os.path.join(out, "engine-data", "root-ca.pem")
            engine.call("POST", "/api/session", {"name": f"001 · {a.label}", "client": a.label, "action": a.task,
                                                 "notes": f"experiment 001; sandbox {sandbox}; command {' '.join(command)}"})
            registered = 0
            for rel, full in sandbox_files(sandbox):
                with open(full, "rb") as f:
                    engine.call("POST", "/api/files", {"name": rel, "base64": base64.b64encode(f.read()).decode(), "origin": "api"})
                registered += 1

            proxy_url = f"http://127.0.0.1:{proxy}"
            env = dict(os.environ)
            for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
                env[k] = proxy_url
            env.pop("NO_PROXY", None)
            env.pop("no_proxy", None)
            # NODE_EXTRA_CA_CERTS adds to Node's roots; the others replace the default bundle, which is fine because
            # every connection of this process goes through the proxy and is signed by its local CA.
            for k in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
                env[k] = ca
            started = time.time()
            with open(os.path.join(out, "agent.stdout"), "wb") as so, open(os.path.join(out, "agent.stderr"), "wb") as se:
                try:
                    code = subprocess.run(command, cwd=sandbox, env=env, stdout=so, stderr=se, timeout=a.timeout).returncode
                except subprocess.TimeoutExpired:
                    code = "timeout"
                except FileNotFoundError:
                    code = "command not found"
            seconds = round(time.time() - started, 1)

            for _ in range(100):  # let streamed responses finish before stopping the proxy
                flows = engine.call("GET", "/api/state")["flows"]
                if all(f["state"] not in ("pending", "streaming") for f in flows):
                    break
                time.sleep(0.1)
            engine.call("POST", "/api/proxy/stop", {})
            archive_bytes = engine.call("GET", "/api/session/download", raw=True)
            with open(os.path.join(out, "session.wscope"), "wb") as f:
                f.write(archive_bytes)
            with open(os.path.join(out, "report.html"), "wb") as f:
                f.write(engine.call("POST", "/api/report", {"redact": False}, raw=True))
        finally:
            engine.proc.terminate()
            engine.proc.wait(timeout=10)

    archive = json.loads(archive_bytes)
    # node prints UTF-8 (→, ←, file names, quoted lines). Without an explicit encoding Python on Windows decodes and
    # writes with cp1252, which has no mapping for some of those bytes (0x90 in "←", many Korean characters).
    trace = subprocess.run(["node", os.path.join(ROOT, "scripts", "provenance_cli.mjs"), os.path.join(out, "session.wscope")],
                           capture_output=True, encoding="utf-8", errors="replace")
    failed = "" if trace.returncode == 0 else f"PROVENANCE CLI FAILED (exit {trace.returncode}); the match section below is missing or partial\n\n"
    summary = f"label: {a.label}\ntask: {a.task}\ncommand: {' '.join(command)}\nexit: {code} after {seconds}s\n" \
              f"local files registered: {registered}\n\n{hosts_section(archive)}\n\n{failed}{trace.stdout}{trace.stderr}"
    with open(os.path.join(out, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(summary)
    with open(os.path.join(out, "run.json"), "w") as f:
        json.dump({"label": a.label, "task": a.task, "command": command, "exit": code, "seconds": seconds,
                   "requests": len(archive["flows"]), "localFiles": registered, "bodyLimit": archive.get("bodyLimit")}, f, indent=2)
    # print() would encode with cp1252 when stdout is a pipe on Windows and fail on the same characters; write UTF-8
    # bytes instead (a Windows console takes UTF-8 bytes through sys.stdout.buffer too)
    sys.stdout.buffer.write(summary.encode("utf-8") + b"\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
