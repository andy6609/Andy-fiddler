#!/usr/bin/env python3
"""Smoke tests for the lab/ learning versions (run after building with WIRESCOPE_BUILD_LAB=ON).

    python3 tests/lab_smoke.py [build-dir] [version ...]

Each version runs against local test servers only. Checks are kept small: they prove the
version does what its header comment claims, not that it is production quality.
"""
import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integration_test as it  # reuse the test HTTP handler, cert helper and curl wrapper

BUILD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(it.ROOT, "build"))
ONLY = set(sys.argv[2:])
failures = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        failures.append(label)


def start(name, *args, env=None):
    proc = subprocess.Popen([f"{BUILD}/lab/{name}", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    time.sleep(0.5)
    return proc


def stop(proc):
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out.decode(errors="replace")


def read_flows(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def v1(tmp, h1):
    print("v1_flow_recorder")
    out = f"{tmp}/v1.jsonl"
    proc = start("v1_flow_recorder", out)
    try:
        rc, body, _ = it.curl(f"http://127.0.0.1:{h1}/hello", proxy=18081)
        check(rc == 0 and body == b"hello world", "GET relayed")
        payload = os.urandom(5000)
        with open(f"{tmp}/p.bin", "wb") as f:
            f.write(payload)
        rc, body, _ = it.curl("--data-binary", f"@{tmp}/p.bin", f"http://127.0.0.1:{h1}/echo", proxy=18081)
        check(rc == 0 and json.loads(body)["sha256"] == hashlib.sha256(payload).hexdigest(), "POST body relayed byte-exact")
        rc, body, _ = it.curl(f"http://127.0.0.1:{h1}/chunked", proxy=18081)
        check(rc == 0 and body == b"part1-part2", "chunked response relayed")
        rc, body, _ = it.curl(f"http://127.0.0.1:{h1}/big", proxy=18081)
        check(rc == 0 and body == it.BIG, "1.5 MiB response relayed in full")
        rc, _, _ = it.curl(f"http://127.0.0.1:{it.free_port()}/x", proxy=18081)
        time.sleep(0.3)
    finally:
        log = stop(proc)
    flows = read_flows(out)
    check(len(flows) == 5, f"5 flows written to JSONL (got {len(flows)})")
    by = {f["path"]: f for f in flows}
    check(base64.b64decode(by["/echo"]["request"]["base64"]) == payload, "request body recorded")
    ch = by.get("/chunked", {})
    check(base64.b64decode(ch["response"]["base64"]) == b"part1-part2" and ch["responseTrailers"] == [["X-Checksum", "abc123"]], "chunked content + trailer recorded")
    big = by["/big"]["response"]
    check(big["total"] == len(it.BIG) and big["captured"] == 1024 * 1024 and big["truncated"], "big body: total counted, 1 MiB kept")
    check(by["/x"]["error"] and by["/x"]["status"] == 0, "refused upstream recorded as error")
    check([e["event"] for e in by["/hello"]["timeline"]] == ["request.headers", "request.end", "response.headers", "response.end"], "timeline events in order")
    check(all(" | " in e for e in by["/hello"]["endpoints"]), "endpoint pairs recorded")
    check("#1 GET" in log, "console summary printed")


def https_server(tmp):
    """HTTPS test server whose certificate chains to tmp/up-ca.pem (created once)."""
    import ssl
    if not os.path.exists(f"{tmp}/server.pem"):
        it.make_certs(tmp)
    hs = http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{tmp}/server.pem", f"{tmp}/server.key")
    hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
    return it.serve(hs).server_address[1]


def v2(tmp, h1):
    print("v2_tls_recorder (passthrough)")
    hs = https_server(tmp)
    out = f"{tmp}/v2.jsonl"
    proc = start("v2_tls_recorder", out)
    try:
        rc, body, err = it.curl("--http1.1", "--cacert", f"{tmp}/up-ca.pem", f"https://localhost:{hs}/hello", proxy=18082)
        check(rc == 0 and body == b"hello world", f"HTTPS through passthrough tunnel {err.strip()}")
        rc, body, _ = it.curl(f"http://127.0.0.1:{h1}/hello", proxy=18082)
        check(rc == 0 and body == b"hello world", "plain HTTP still works")
        time.sleep(0.3)
    finally:
        stop(proc)
    flows = read_flows(out)
    t = [f for f in flows if f["method"] == "CONNECT"]
    check(len(t) == 1, "one CONNECT flow")
    if t:
        o = t[0]["observed"]
        check(o["client"]["firstRecordName"] == "Handshake" and o["client"]["sni"] == "localhost", "ClientHello seen: Handshake record, SNI=localhost")
        check(o["server"]["firstRecordType"] == 22, "server answers with a Handshake record")
        check(t[0]["request"]["total"] > 0 and t[0]["response"]["total"] > len("hello world"), "encrypted byte counts recorded")
        check(b"hello world" not in base64.b64decode(t[0]["response"]["base64"]), "tunnel bytes are ciphertext (plaintext body not visible)")

    print("v2_tls_recorder (--mitm)")
    out = f"{tmp}/v2m.jsonl"
    env = dict(os.environ, SSL_CERT_FILE=f"{tmp}/up-ca.pem")   # upstream verification trusts the test server CA
    proc = start("v2_tls_recorder", out, "--mitm", env=env)
    ca = out + ".ca.pem"
    try:
        rc, body, err = it.curl("--http1.1", "--cacert", ca, f"https://localhost:{hs}/hello", proxy=18082)
        check(rc == 0 and body == b"hello world", f"HTTPS via MITM with the lab CA {err.strip()}")
        payload = os.urandom(3000)
        with open(f"{tmp}/p2.bin", "wb") as f:
            f.write(payload)
        rc, body, _ = it.curl("--http1.1", "--cacert", ca, "--data-binary", f"@{tmp}/p2.bin", f"https://localhost:{hs}/echo", proxy=18082)
        check(rc == 0 and json.loads(body)["len"] == 3000, "HTTPS POST relayed")
        rc, body, _ = it.curl("--http2", "--cacert", ca, f"https://localhost:{hs}/chunked", proxy=18082)
        check(rc == 0 and body == b"part1-part2", "client asking for h2 is served over HTTP/1.1 (ALPN)")
        rc, _, _ = it.curl("--http1.1", f"https://localhost:{hs}/hello", proxy=18082)
        check(rc != 0, "client without the lab CA refuses the forged certificate")
        time.sleep(0.3)
    finally:
        stop(proc)
    flows = read_flows(out)
    https = [f for f in flows if f["scheme"] == "https"]
    check(len(https) == 3 and all(f["tls"].startswith("TLS") for f in https), "3 decrypted HTTPS flows with TLS version")
    echo = next((f for f in https if f["path"] == "/echo"), None)
    check(echo and base64.b64decode(echo["request"]["base64"]) == payload, "decrypted request body recorded")
    tunnels = [f for f in flows if f["method"] == "CONNECT"]
    check(any(t["observed"].get("clientAlpn") == "http/1.1" for t in tunnels), "ALPN http/1.1 recorded on the tunnel")
    check(any("client TLS handshake failed" in t["error"] for t in tunnels), "untrusted-CA handshake failure recorded")


VERSIONS = [("v1", v1), ("v2", v2)]


def main():
    tmp = tempfile.mkdtemp(prefix="ws-lab-")
    h1 = it.serve(http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler)).server_address[1]
    for name, fn in VERSIONS:
        if not ONLY or name in ONLY:
            fn(tmp, h1)
    print(f"{len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
