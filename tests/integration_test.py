#!/usr/bin/env python3
"""End-to-end test: real clients -> WireScope proxy -> local test servers.

Runs on a development host (macOS/Linux) with curl (HTTP/2 enabled), openssl and nghttpd.
It does not cover Npcap or Windows trust-store behaviour.

    python3 tests/integration_test.py [path/to/build]
"""
import base64
import gzip
import hashlib
import http.server
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build"))
NGHTTPD = os.environ.get("NGHTTPD") or shutil.which("nghttpd") or "/opt/homebrew/opt/nghttp2/bin/nghttpd"
OPENSSL = shutil.which("openssl")

failures = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        failures.append(label)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


BIG = bytes(range(256)) * 6144  # 1.5 MiB, larger than the 1 MiB capture limit
GZ_JSON = gzip.compress(json.dumps({"compressed": True, "items": list(range(50))}).encode())
SSE = b'event: message_start\ndata: {"type":"message_start"}\n\nevent: delta\ndata: {"delta":{"text":"Hel"}}\n\nevent: delta\ndata: {"delta":{"text":"lo"}}\n\n'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, status, body, ctype, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hello":
            self.send(200, b"hello world", "text/plain")
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Checksum")
            self.end_headers()
            for part in (b"part1-", b"part2"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\nX-Checksum: abc123\r\n\r\n")
        elif self.path == "/gzip":
            self.send(200, GZ_JSON, "application/json", [("Content-Encoding", "gzip")])
        elif self.path == "/big":
            self.send(200, BIG, "application/octet-stream")
        elif self.path == "/sse":
            self.send(200, SSE, "text/event-stream")
        else:
            self.send(404, b"not found", "text/plain")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send(200, json.dumps({"len": len(body), "sha256": hashlib.sha256(body).hexdigest()}).encode(), "application/json")


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def make_certs(d):
    run = lambda *a: subprocess.run([OPENSSL, *a], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=WireScope Test Upstream CA",
        "-keyout", f"{d}/up-ca.key", "-out", f"{d}/up-ca.pem")
    run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", f"{d}/server.key", "-out", f"{d}/server.csr")
    with open(f"{d}/ext.cnf", "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", f"{d}/server.csr", "-CA", f"{d}/up-ca.pem", "-CAkey", f"{d}/up-ca.key", "-CAcreateserial",
        "-days", "2", "-extfile", f"{d}/ext.cnf", "-out", f"{d}/server.pem")


class Engine:
    def __init__(self, tmp):
        self.port = free_port()
        env = dict(os.environ, SSL_CERT_FILE=f"{tmp}/up-ca.pem")  # upstream verification trusts the test CA
        self.proc = subprocess.Popen([f"{BUILD}/WireScope", "--no-open", "--port", str(self.port), "--data", f"{tmp}/data",
                                      "--web", f"{BUILD}/web"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(100):
            try:
                self.token = json.load(urllib.request.urlopen(self.base + "/api/bootstrap"))["token"]
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("engine did not start: " + self.proc.stdout.read().decode())

    def request(self, method, path, body=None, headers=None, raw=False, token=True):
        h = {"X-WireScope-Token": self.token} if token else {}
        if body is not None:  # urllib would default to form encoding, which cpp-httplib caps at 8 KiB
            h["Content-Type"] = "application/octet-stream" if isinstance(body, bytes) else "application/json"
        h.update(headers or {})
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req) as r:
                out = r.read()
                return r.status, (out if raw else json.loads(out))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def flows(self):
        return self.request("GET", "/api/state")[1]["flows"]

    def flow(self, fid):
        return self.request("GET", f"/api/flows/{fid}")[1]


def curl(*args, proxy):
    r = subprocess.run(["curl", "-sS", "--max-time", "20", "-x", f"http://127.0.0.1:{proxy}", *args], capture_output=True)
    return r.returncode, r.stdout, r.stderr.decode()


def body_of(detail, side):
    return base64.b64decode(detail[side]["body"]["base64"] or "")


def find(flows, **kw):
    return [f for f in flows if all(f.get(k) == v for k, v in kw.items())]


def wait_settled(engine, count, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        flows = engine.flows()
        if len(flows) >= count and all(f["state"] not in ("pending", "streaming") for f in flows):
            return flows
        time.sleep(0.1)
    return engine.flows()


def synthetic_pcap():
    """Ethernet/IPv4/TCP handshake + HTTP request, and a DNS query, as classic pcap."""
    def ip(proto, payload):
        h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + h + payload
    def tcp(seq, flags, data=b""):
        return struct.pack("!HHIIBBHHH", 50000, 80, seq, 0, 0x50, flags, 65535, 0, 0) + data
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
    frames = [ip(6, tcp(100, 0x02)), ip(6, tcp(101, 0x18, b"GET /a HTTP/1.1\r\n")), ip(6, tcp(118, 0x18, b"Host: x\r\n\r\n")),
              ip(17, struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns)]
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="wirescope-it-")
    procs = []
    try:
        make_certs(tmp)
        h1 = serve(http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Handler))
        hs = http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{tmp}/server.pem", f"{tmp}/server.key")
        hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
        serve(hs)
        os.makedirs(f"{tmp}/htdocs")
        for i in range(5):
            with open(f"{tmp}/htdocs/f{i}.json", "w") as f:
                json.dump({"file": i, "pad": "x" * (2000 * i)}, f)
        h2port = free_port()
        procs.append(subprocess.Popen([NGHTTPD, f"--address=127.0.0.1", f"--htdocs={tmp}/htdocs", "--trailer=x-h2-trailer: yes",
                                       str(h2port), f"{tmp}/server.key", f"{tmp}/server.pem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        engine = Engine(tmp)
        procs.append(engine.proc)
        H1, HS = h1.server_address[1], hs.server_address[1]

        print("API boundary")
        check(engine.request("GET", "/api/state", token=False)[0] == 403, "missing token rejected")
        check(engine.request("GET", "/api/state", headers={"Host": "evil.example"})[0] == 403, "foreign Host rejected (DNS rebinding)")
        check(engine.request("POST", "/api/sample", {}, headers={"Origin": "http://evil.example"})[0] == 403, "foreign Origin rejected")

        proxy = free_port()
        status, st = engine.request("POST", "/api/proxy/start", {"port": proxy, "mitm": True})
        check(status == 200 and st["running"], "proxy starts with MITM")
        ca = f"{tmp}/data/root-ca.pem"
        status, info = engine.request("GET", "/api/ca")
        check(info["exists"] and len(info["fingerprint"]) == 64, "local CA created with DER fingerprint")
        der = subprocess.run([OPENSSL, "x509", "-in", ca, "-outform", "DER"], capture_output=True).stdout
        check(info["fingerprint"] == hashlib.sha256(der).hexdigest(), "fingerprint matches openssl DER SHA-256")

        print("HTTP/1.1 through the proxy")
        rc, out, _ = curl(f"http://127.0.0.1:{H1}/hello", proxy=proxy)
        check(rc == 0 and out == b"hello world", "plain GET relayed unchanged")
        payload = os.urandom(70000)
        with open(f"{tmp}/payload.bin", "wb") as f:
            f.write(payload)
        rc, out, _ = curl("--data-binary", f"@{tmp}/payload.bin", "-H", "Content-Type: application/octet-stream", f"http://127.0.0.1:{H1}/upload", proxy=proxy)
        check(rc == 0 and json.loads(out)["sha256"] == hashlib.sha256(payload).hexdigest(), "binary POST body relayed byte-exact")
        rc, out, _ = curl(f"http://127.0.0.1:{H1}/chunked", proxy=proxy)
        check(rc == 0 and out == b"part1-part2", "chunked response relayed")
        rc, out, _ = curl("--compressed", f"http://127.0.0.1:{H1}/gzip", proxy=proxy)
        check(rc == 0 and json.loads(out)["compressed"] is True, "gzip response relayed")
        rc, out, _ = curl(f"http://127.0.0.1:{H1}/big", proxy=proxy)
        check(rc == 0 and out == BIG, "1.5 MiB response relayed in full")
        rc, out, _ = curl(f"http://127.0.0.1:{H1}/sse", proxy=proxy)
        check(rc == 0 and out == SSE, "event stream relayed")

        print("HTTPS (TLS terminated) and HTTP/2")
        rc, out, err = curl("--http1.1", "--cacert", ca, f"https://localhost:{HS}/hello", proxy=proxy)
        check(rc == 0 and out == b"hello world", f"HTTPS/1.1 via local CA {err.strip()}")
        urls = [f"https://localhost:{h2port}/f{i}.json" for i in range(5)]
        rc, out, err = curl("--http2", "--cacert", ca, "-Z", "--parallel-max", "5", *urls, proxy=proxy)
        check(rc == 0 and out.count(b'"file"') == 5, f"5 parallel HTTP/2 requests on a non-443 port {err.strip()}")
        rc, out, err = curl("--http2", "--cacert", ca, "-d", "hello-h2", f"https://localhost:{h2port}/f1.json", proxy=proxy)
        check(rc == 0, f"HTTP/2 POST with body {err.strip()}")

        print("Recorded flows")
        flows = wait_settled(engine, 13)
        hello = find(flows, path="/hello", protocol="HTTP/1.1")
        check(len(hello) == 2 and all(f["status"] == 200 and f["state"] == "complete" for f in hello), "two /hello flows complete with 200")
        check(any(f.get("tls") for f in hello) and any(not f.get("tls") for f in hello), "TLS version recorded only for the HTTPS one")
        up = find(flows, path="/upload")[0]
        d = engine.flow(up["id"])
        check(body_of(d, "request") == payload and d["request"]["body"]["sha256"] == hashlib.sha256(payload).hexdigest(), "captured request body and sha256 match what curl sent")
        check(up["port"] == H1, "upstream port recorded")
        ch = engine.flow(find(flows, path="/chunked")[0]["id"])
        check(body_of(ch, "response") == b"part1-part2", "chunked body recorded de-chunked")
        check(ch.get("responseTrailers") == [["X-Checksum", "abc123"]], "HTTP/1.1 chunked trailer recorded")
        big = engine.flow(find(flows, path="/big")[0]["id"])
        rb = big["response"]["body"]
        check(rb["total"] == len(BIG) and rb["captured"] == 1024 * 1024 and rb["truncated"] and rb["sha256"] == "", "large body: total counted, capture capped, no partial hash")
        gz = engine.flow(find(flows, path="/gzip")[0]["id"])
        check(gzip.decompress(body_of(gz, "response")) == gzip.decompress(GZ_JSON), "gzip body kept as received (encoded)")
        h2 = sorted(find(flows, protocol="HTTP/2", method="GET"), key=lambda f: f["streamId"])
        check(len(h2) == 5, f"5 HTTP/2 GET flows recorded (got {len(h2)})")
        check(len({f["connection"] for f in h2}) == 1 and len({f["streamId"] for f in h2}) == 5, "HTTP/2 flows share one connection with distinct stream IDs")
        check(all(f["status"] == 200 and f["state"] == "complete" for f in h2), "HTTP/2 flows complete")
        d4 = engine.flow(next(f["id"] for f in h2 if f["path"] == "/f4.json"))
        check(json.loads(body_of(d4, "response"))["file"] == 4, "HTTP/2 response body attributed to the right stream")
        check(d4.get("responseTrailers") == [["x-h2-trailer", "yes"]], "HTTP/2 response trailer forwarded and recorded")
        h2post = find(flows, protocol="HTTP/2", method="POST")
        check(h2post and body_of(engine.flow(h2post[0]["id"]), "request") == b"hello-h2", "HTTP/2 request body recorded")
        tunnels = find(flows, method="CONNECT")
        check(len(tunnels) >= 2 and all(t.get("alpn") in ("h2", "http/1.1") for t in tunnels), "CONNECT flows record negotiated ALPN")
        check(all(len(f.get("packetKeys", [])) == 2 for f in hello), "client and upstream endpoint keys recorded")

        print("Passthrough and errors")
        engine.request("POST", "/api/proxy/stop", {})
        engine.request("POST", "/api/proxy/start", {"port": proxy, "mitm": False})
        before = len(engine.flows())
        rc, out, _ = curl("--http1.1", "--cacert", f"{tmp}/up-ca.pem", f"https://localhost:{HS}/hello", proxy=proxy)
        check(rc == 0 and out == b"hello world", "TLS passthrough works with the server's own certificate")
        rc, _, _ = curl(f"http://127.0.0.1:{free_port()}/nothing", proxy=proxy)
        flows = wait_settled(engine, before + 2)
        tunnel = [f for f in flows[before:] if f["method"] == "CONNECT"]
        check(tunnel and tunnel[0].get("encrypted") and tunnel[0]["requestBytes"] > 0 and tunnel[0]["responseBytes"] > 0, "passthrough tunnel records encrypted byte counts")
        if tunnel:
            raw = body_of(engine.flow(tunnel[0]["id"]), "request")
            check(raw[:1] == b"\x16", "tunnel bytes start with a TLS handshake record")
        errs = [f for f in flows[before:] if f["state"] == "error"]
        check(errs and "Upstream connection failed" in errs[0].get("error", ""), "refused upstream recorded as error flow")
        engine.request("POST", "/api/proxy/stop", {})

        print("Exports and imports")
        status, html = engine.request("POST", "/api/report", {"redact": True}, raw=True)
        text = html.decode()
        check(status == 200 and "WIRESCOPE_ARCHIVE" in text and "</html>" in text, "redacted HTML report produced")
        enc = text.split("atob('")[1].split("')")[0]
        archive = json.loads(base64.b64decode(enc))
        check(archive["redacted"] and all(not f["request"]["body"]["base64"] for f in archive["flows"]) and archive["packets"] == [], "redacted report has no bodies or packets")
        status, html = engine.request("POST", "/api/report", {"redact": False, "ids": [up["id"]]}, raw=True)
        archive = json.loads(base64.b64decode(html.decode().split("atob('")[1].split("')")[0]))
        check(len(archive["flows"]) == 1 and base64.b64decode(archive["flows"][0]["request"]["body"]["base64"]) == payload, "selected-flow report keeps the raw body")
        with open(f"{tmp}/report.html", "wb") as f:
            f.write(html)
        status, saved = engine.request("GET", "/api/session/download", raw=True)
        count = len(engine.flows())
        engine.request("POST", "/api/session/new", {"name": "empty"})
        check(len(engine.flows()) == 0, "new session clears records")
        status, r = engine.request("POST", "/api/session/import", saved)
        check(status == 200 and len(engine.flows()) == count, f"session archive round-trips {r if status != 200 else ''}")
        status, r = engine.request("POST", "/api/pcap/import", synthetic_pcap())
        check(status == 200 and r["packets"] == 4, "pcap import")
        st = engine.request("GET", "/api/state")[1]
        protos = [p["protocol"] for p in st["packets"]]
        check(protos == ["TCP", "HTTP", "TCP", "DNS"] or protos == ["TCP", "HTTP", "HTTP", "DNS"], f"imported packets decoded ({protos})")
        key = st["packets"][1]["key"]
        status, stream = engine.request("GET", "/api/stream?key=" + urllib.parse.quote(key))
        joined = b"".join(base64.b64decode(c["base64"]) for c in stream[0]["chunks"] if "base64" in c)
        check(joined == b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", "TCP stream preview reassembles the request")
        status, pcapng = engine.request("GET", "/api/pcap/download", raw=True)
        check(pcapng[:4] == b"\x0a\x0d\x0d\x0a", "pcapng export")
        status, ifs = engine.request("GET", "/api/interfaces")
        check(status == 200 and "interfaces" in ifs, "interface listing answers")
        print(f"\nartifacts kept in {tmp}" if failures else "")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if not failures:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
