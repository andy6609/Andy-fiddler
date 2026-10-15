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
import socket
import struct
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


LAB_PORTS = {"v1_flow_recorder": 18081, "v2_tls_recorder": 18082, "v3_h2_observer": 18083}


def start(name, *args, env=None):
    proc = subprocess.Popen([f"{BUILD}/lab/{name}", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    port = LAB_PORTS.get(name)
    for _ in range(100):  # key generation can take a moment; wait until the listener is up
        if port is None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
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


def h2_server(tmp, files):
    """nghttpd serving `files` (name -> bytes) over TLS with a response trailer."""
    if not os.path.exists(f"{tmp}/server.pem"):
        it.make_certs(tmp)
    docs = f"{tmp}/h2docs"
    os.makedirs(docs, exist_ok=True)
    for name, data in files.items():
        with open(f"{docs}/{name}", "wb") as f:
            f.write(data)
    port = it.free_port()
    proc = subprocess.Popen([it.NGHTTPD, "--address=127.0.0.1", f"--htdocs={docs}", "--trailer=x-h2-trailer: yes", str(port),
                             f"{tmp}/server.key", f"{tmp}/server.pem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    return port, proc


H2_FILES = {f"f{i}.json": json.dumps({"file": i, "pad": "x" * (3000 * i)}).encode() for i in range(3)}


def v3(tmp, h1):
    print("v3_h2_observer")
    port, ng = h2_server(tmp, H2_FILES)
    out = f"{tmp}/v3.jsonl"
    proc = start("v3_h2_observer", out, env=dict(os.environ, SSL_CERT_FILE=f"{tmp}/up-ca.pem"))
    try:
        urls = [f"https://localhost:{port}/{n}" for n in H2_FILES]
        rc, body, err = it.curl("--http2", "--cacert", out + ".ca.pem", "-Z", "--parallel-max", "3", *urls, proxy=18083)
        check(rc == 0 and body.count(b'"file"') == 3, f"3 parallel h2 requests relayed byte-for-byte {err.strip()}")
        rc, body, _ = it.curl("--http2", "--cacert", out + ".ca.pem", "-d", "posted-body", urls[1], proxy=18083)
        check(rc == 0, "h2 POST relayed")
        time.sleep(0.5)
    finally:
        log = stop(proc)
        ng.terminate()
    records = read_flows(out)
    conns = [r for r in records if r.get("kind") == "h2-connection"]
    streams = [r for r in records if r.get("kind") == "h2-stream"]
    check(len(conns) == 2 and all(c["alpn"] == "h2" for c in conns), "two h2 connections recorded")
    gets = sorted((st for st in streams if st["method"] == "GET"), key=lambda st: st["path"])
    check(len(gets) == 3 and all(st["status"] == 200 and st["state"] == "complete" for st in gets), "HPACK: 3 GET streams with :path and :status 200")
    check(all(base64.b64decode(st["response"]["base64"]) == H2_FILES[st["path"][1:]] for st in gets), "response body per stream matches the file")
    check(all(st["responseTrailers"] == [["x-h2-trailer", "yes"]] for st in gets), "trailer HEADERS recognised as trailers")
    check(all(any(k == "user-agent" for k, _ in st["requestHeaders"]) for st in gets), "dynamic-table headers decoded on later streams too")
    post = [st for st in streams if st["method"] == "POST"]
    check(post and base64.b64decode(post[0]["request"]["base64"]) == b"posted-body", "h2 request body recorded")
    if conns:
        c = max(conns, key=lambda c: len(c["streams"]))
        types = {(f["dir"], f["type"]) for f in c["frames"]}
        check({("C->S", "SETTINGS"), ("S->C", "SETTINGS"), ("C->S", "HEADERS"), ("S->C", "DATA")} <= types, "SETTINGS/HEADERS/DATA frames seen both ways")
        ids = sorted(s["stream"] for s in c["streams"])
        check(ids == [1, 3, 5], f"client streams are odd: {ids}")
        sizes = sorted(s["dataServerToClient"] for s in c["streams"])
        check(sizes == sorted(len(v) for v in H2_FILES.values()), "DATA bytes per stream == file sizes")
        check(any(f["type"] == "SETTINGS" and "settings" in f for f in c["frames"]), "SETTINGS parameters decoded")
    check("END_STREAM" in log, "frame log printed")
    return conns


def pcapng(packets):
    """packets: list of (linktype, bytes, time_us). One IDB per link type, default microsecond resolution."""
    def block(t, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for link, data, ts in packets:
        if link not in ifs:
            ifs[link] = len(ifs)
            out += block(1, struct.pack("<HHI", link, 0, 65535))
        out += block(6, struct.pack("<IIIII", ifs[link], ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    return out


def udp_dns(name_bytes, ipv6=False, vlan=False):
    dns = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + name_bytes + b"\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 5353, 53, 8 + len(dns), 0) + dns
    if ipv6:
        ip = struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + bytes(15) + b"\x01" + bytes(15) + b"\x02"
        eth = b"\x02" * 12 + b"\x86\xdd"
    else:
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        eth = b"\x02" * 12 + (b"\x81\x00\x00\x2a\x08\x00" if vlan else b"\x08\x00")
    return eth + ip + udp


def run(name, *args):
    r = subprocess.run([f"{BUILD}/lab/{name}", *args], capture_output=True, env=dict(os.environ, NO_COLOR="1"))
    return r.returncode, r.stdout.decode(errors="replace")


def v4(tmp, h1):
    print("v4_packet_decoder")
    classic = f"{tmp}/syn.pcap"
    with open(classic, "wb") as f:
        f.write(it.synthetic_pcap())
    rc, out = run("v4_packet_decoder", classic)
    check(rc == 0 and "GET /a HTTP/1.1" in out and "query example.com" in out and "[SYN]" in out, "classic pcap list: SYN, HTTP request line, DNS name")
    rc, out = run("v4_packet_decoder", classic, "2", "--field", "TCP flags")
    row = [l for l in out.splitlines() if l.startswith("TCP flags") or " TCP flags " in l]
    check(row and row[0].split()[-2:] == ["47", "1"], "TCP flags field at offset 47, length 1")
    marks = [l for l in out.splitlines() if "^^" in l]
    check(len(marks) == 1 and marks[0].index("^^") == 8 + 15 * 3, "^^ marker under byte 47 (row 0x20, column 15)")

    loop = b"\xc0\x0c"  # compression pointer to itself
    lo = struct.pack("<I", 2) + udp_dns(b"\x01a\x00")[14:]  # BSD loopback: 4-byte AF header then IPv4
    ng = f"{tmp}/mix.pcapng"
    with open(ng, "wb") as f:
        f.write(pcapng([(1, udp_dns(b"\x03www\x07example\x03com\x00", ipv6=True), 1_700_000_000_000_000),
                        (1, udp_dns(b"\x04vlan\x00", vlan=True), 1_700_000_000_500_000),
                        (0, lo, 1_700_000_001_000_000),
                        (1, udp_dns(loop), 1_700_000_002_000_000)]))
    rc, out = run("v4_packet_decoder", ng)
    lines = out.splitlines()[1:]
    check(rc == 0 and len(lines) == 4, "pcapng: 4 packets across two interfaces")
    check("query www.example.com" in lines[0] and "[0:0:0:0:0:0:0:1]:5353" in lines[0], "IPv6 + DNS decoded, [addr]:port")
    check("query vlan" in lines[1], "VLAN tag skipped")
    check("query a" in lines[2], "BSD loopback link type decoded")
    check("!!" in lines[3] and "DNS" in lines[3], "DNS pointer loop reported, not followed forever")
    rc, out = run("v4_packet_decoder", ng, "2")
    check("VLAN id" in out and "42" in out, "VLAN id field shown")
    with open(f"{tmp}/cut.pcap", "wb") as f:
        f.write(it.synthetic_pcap()[:-5])
    rc, out = run("v4_packet_decoder", f"{tmp}/cut.pcap")
    check(rc == 1 and "잘림" in out, "truncated file rejected with a reason")


def tcp_conversation():
    """A full HTTP-over-TCP conversation as classic pcap, with deliberate capture problems:
    client data arrives out of order, one server segment is retransmitted, one is missing."""
    C, S = (bytes([10, 0, 0, 1]), 50000), (bytes([10, 0, 0, 2]), 80)
    def frame(src, dst, seq, ack, flags, data=b""):
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 0x50, flags, 65535, 0, 0) + data
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src[0], dst[0])
        return b"\x02" * 12 + b"\x08\x00" + ip + tcp
    req1, req2 = b"GET /index.html HTTP/1.1\r\n", b"Host: example\r\n\r\n"
    r1, r2, r3 = b"HTTP/1.1 200 OK\r\n", b"Content-Length: 5\r\n\r\n", b"hello"
    cs, ss = 1000, 5000  # initial sequence numbers
    pkts = [
        frame(C, S, cs, 0, 0x02),                                         # SYN
        frame(S, C, ss, cs + 1, 0x12),                                    # SYN+ACK
        frame(C, S, cs + 1, ss + 1, 0x10),                                # ACK
        frame(C, S, cs + 1 + len(req1), ss + 1, 0x18, req2),              # 2nd half first (out of order)
        frame(C, S, cs + 1, ss + 1, 0x18, req1),                          # 1st half
        frame(S, C, ss + 1, cs + 1 + len(req1 + req2), 0x18, r1),
        frame(S, C, ss + 1, cs + 1 + len(req1 + req2), 0x18, r1),        # retransmission of r1
        # r2 is never captured -> gap of len(r2)
        frame(S, C, ss + 1 + len(r1 + r2), cs + 1 + len(req1 + req2), 0x18, r3),
        frame(C, S, cs + 1 + len(req1 + req2), ss + 1 + len(r1 + r2 + r3), 0x11),   # FIN+ACK
        frame(S, C, ss + 1 + len(r1 + r2 + r3), cs + 2 + len(req1 + req2), 0x11),   # FIN+ACK
        frame(C, S, cs + 2 + len(req1 + req2), ss + 2 + len(r1 + r2 + r3), 0x10),   # ACK
    ]
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, fr in enumerate(pkts):
        out += struct.pack("<IIII", 1700000000, i * 1000, len(fr), len(fr)) + fr
    return out, req1 + req2, (r1, r2, r3)


def v5(tmp, h1):
    print("v5_tcp_stream")
    pcap, request, (r1, r2, r3) = tcp_conversation()
    path = f"{tmp}/conv.pcap"
    with open(path, "wb") as f:
        f.write(pcap)
    with open(f"{tmp}/mixed.pcap", "wb") as f:
        f.write(it.synthetic_pcap())
    rc, out = run("v5_tcp_stream", path)
    check(rc == 0 and "1 connections" in out and "10.0.0.1:50000 -> 10.0.0.2:80" in out, "one connection, client = SYN sender")
    life = [l.split("->", 1)[1].split()[1] for l in out.splitlines() if l.strip().startswith("+")]
    check(life == ["SYN", "SYN+ACK", "FIN+ACK", "FIN+ACK"], f"handshake and teardown in order: {life}")
    rc, out = run("v5_tcp_stream", f"{tmp}/mixed.pcap")
    check(rc == 0 and "(SYN" not in out and "1 connections" in out, "UDP ignored, SYN seen in synthetic capture")
    rc, out = run("v5_tcp_stream", path, "1")
    check(request.decode() in out, "out-of-order client segments put back in order")
    check("#4  out of order: arrived before #5" in out, "out-of-order arrival reported")
    check("#7 retransmission" in out, "retransmitted server segment detected and dropped")
    check(f"GAP  {len(r2)} bytes not captured" in out and f"«{len(r2)} bytes missing»hello" in out, "missing bytes shown as a gap, not invented")
    check(f"{len(r1) + len(r3)} bytes reassembled, {len(r2)} bytes missing" in out, "per-direction totals")
    rc, out = run("v5_tcp_stream", path, "1", "--hex")
    check("47 45 54 20 2f 69 6e 64" in out, "hex view of the request")
    return path, request, (r1, r2, r3)


VERSIONS = [("v1", v1), ("v2", v2), ("v3", v3), ("v4", v4), ("v5", v5)]


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
