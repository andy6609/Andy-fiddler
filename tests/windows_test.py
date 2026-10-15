#!/usr/bin/env python3
"""Windows-only end-to-end checks: features that exist only in the Windows build.

    python tests/windows_test.py [path/to/build/Release]

1. Process attribution: a flow names the process that opened the proxy connection. The test starts
   curl.exe and python.exe children itself, so it knows the real PIDs and compares them with what
   WireScope recorded (pid, exe name/path, command line, parent = this test process).

Reuses tests/integration_test.py for the local servers, certificates and the engine wrapper.
"""
import base64
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integration_test as it  # noqa: E402

failures = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        failures.append(label)


def run_child(args):
    """Start a client ourselves so we know its PID, wait for it, return (pid, returncode, stdout)."""
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(timeout=30)
    return proc.pid, proc.returncode, out


def same_file(a, b):
    return os.path.normcase(os.path.abspath(a or "")) == os.path.normcase(os.path.abspath(b or ""))


def process_checks(engine, tmp, h1, hs, h2port, proxy):
    ca = f"{tmp}/data/root-ca.pem"
    print("Process attribution (GetExtendedTcpTable at accept)")
    url = f"http://127.0.0.1:{h1}/hello?who=curl-plain"
    pid, rc, out = run_child([it.CURL, "-sS", "-x", f"http://127.0.0.1:{proxy}", url])
    check(rc == 0 and out == b"hello world", "curl.exe child got its response through the proxy")
    flows = it.wait_settled(engine, 1)
    plain = [f for f in flows if f.get("path") == "/hello?who=curl-plain"]
    check(len(plain) == 1, "flow recorded")
    if plain:
        summary = plain[0].get("process") or {}
        check(summary.get("pid") == pid, f"list row: process.pid == curl child PID ({summary.get('pid')} vs {pid})")
        check(str(summary.get("name", "")).lower() == "curl.exe", f"list row: process.name == curl.exe ({summary.get('name')})")
        check("commandLine" not in summary and "path" not in summary, "list row keeps only pid/name (detail has the rest)")
        d = engine.flow(plain[0]["id"]).get("process") or {}
        print(f"  info process detail: {json.dumps(d, ensure_ascii=False)}")
        check(same_file(d.get("path"), it.CURL), f"detail: path is the curl.exe we started ({d.get('path')})")
        check(url in d.get("commandLine", ""), "detail: command line contains the URL we passed")
        check(d.get("parentPid") == os.getpid(), f"detail: parentPid == this test's PID ({d.get('parentPid')} vs {os.getpid()})")
        check(str(d.get("parentName", "")).lower().startswith("python"), f"detail: parentName is python ({d.get('parentName')})")
        check("error" not in d, f"detail: no lookup error ({d.get('error', '')})")

    before = len(engine.flows())
    pid, rc, _ = run_child([it.CURL, "-sS", "--http1.1", "--cacert", ca, "-x", f"http://127.0.0.1:{proxy}", f"https://localhost:{hs}/hello"])
    flows = it.wait_settled(engine, before + 2)[before:]
    tunnel = [f for f in flows if f.get("method") == "CONNECT"]
    inner = [f for f in flows if f.get("path") == "/hello"]
    check(rc == 0 and tunnel and inner, "HTTPS via CONNECT recorded (tunnel + decrypted request)")
    check(all((f.get("process") or {}).get("pid") == pid for f in tunnel + inner), "CONNECT flow and the request inside it carry the same curl PID")

    before = len(engine.flows())
    urls = [f"https://localhost:{h2port}/f{i}.json" for i in range(3)]
    pid, rc, _ = run_child([it.CURL, "-sS", "--http2", "--cacert", ca, "-Z", "-x", f"http://127.0.0.1:{proxy}", *urls])
    flows = it.wait_settled(engine, before + 4)[before:]
    h2 = [f for f in flows if f.get("protocol") == "HTTP/2"]
    check(rc == 0 and len(h2) == 3, f"3 HTTP/2 streams recorded (got {len(h2)})")
    check(h2 and all((f.get("process") or {}).get("pid") == pid for f in h2), "every HTTP/2 stream flow carries the curl PID")

    # A second, different client: python.exe using urllib with an explicit proxy.
    before = len(engine.flows())
    code = ("import urllib.request,sys;"
            f"o=urllib.request.build_opener(urllib.request.ProxyHandler({{'http':'http://127.0.0.1:{proxy}'}}));"
            f"sys.stdout.write(o.open('http://127.0.0.1:{h1}/hello?who=python').read().decode())")
    pid, rc, out = run_child([sys.executable, "-c", code])
    flows = it.wait_settled(engine, before + 1)[before:]
    py = [f for f in flows if f.get("path") == "/hello?who=python"]
    check(rc == 0 and out == b"hello world" and py, "python.exe child (urllib, explicit proxy) recorded")
    if py:
        p = py[0].get("process") or {}
        check(p.get("pid") == pid and str(p.get("name", "")).lower().startswith("python"),
              f"python child attributed to its own PID and exe ({p.get('pid')} {p.get('name')} vs {pid})")

    status, html = engine.request("POST", "/api/report", {"redact": True}, raw=True)
    archive = json.loads(base64.b64decode(html.decode().split("atob('")[1].split("')")[0]))
    procs = [f["process"] for f in archive["flows"] if f.get("process")]
    check(procs and all(p.get("commandLine") == "[redacted]" and p.get("path") == "[redacted]" for p in procs if "path" in p),
          "redacted report hides process path and command line")
    check(procs and all("pid" in p and "name" in p for p in procs), "redacted report keeps pid and exe name")


def main():
    if os.name != "nt":
        print("Windows only; nothing to do on this host")
        return 0
    tmp = tempfile.mkdtemp(prefix="wirescope-win-")
    procs = []
    try:
        it.make_certs(tmp)
        h1 = it.serve(http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler)).server_address[1]
        hs_server = http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{tmp}/server.pem", f"{tmp}/server.key")
        hs_server.socket = ctx.wrap_socket(hs_server.socket, server_side=True)
        hs = it.serve(hs_server).server_address[1]
        os.makedirs(f"{tmp}/htdocs")
        for i in range(3):
            with open(f"{tmp}/htdocs/f{i}.json", "w") as f:
                json.dump({"file": i}, f)
        h2port = it.free_port()
        procs.append(subprocess.Popen([*it.H2D, "--address=127.0.0.1", f"--htdocs={tmp}/htdocs", "--trailer=x-h2-trailer: yes",
                                       str(h2port), f"{tmp}/server.key", f"{tmp}/server.pem"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        it.wait_port(h2port)
        engine = it.Engine(tmp)
        procs.append(engine.proc)
        proxy = it.free_port()
        status, st = engine.request("POST", "/api/proxy/start", {"port": proxy, "mitm": True})
        check(status == 200 and st["running"], "proxy starts")
        process_checks(engine, tmp, h1, hs, h2port, proxy)
        engine.request("POST", "/api/proxy/stop", {})
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    print(f"{len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
