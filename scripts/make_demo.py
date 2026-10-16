#!/usr/bin/env python3
"""Build the public demo (site/demo.html): an offline WireScope report with known, harmless data.

    python3 scripts/make_demo.py [build-dir]

Where the data comes from, so the demo never pretends to be something it isn't:
  - Requests: real requests sent with curl through WireScope's proxy to local test servers on
    127.0.0.1 (HTTP/1.1, HTTPS via the local CA, HTTP/2). No real AI service is involved; the
    "agent" request bodies are made up.
  - Packets: a hand-built pcap (a TCP conversation with out-of-order, retransmitted and missing
    segments, plus one DNS query). It is not linked to the requests above, because the demo is
    generated on a machine without packet-capture permission.
"""
import base64
import http.server
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.dont_write_bytecode = True
import integration_test as it  # noqa: E402  (test servers, certs, curl wrapper, Engine)

it.BUILD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build"))
OUT = os.path.join(ROOT, "site", "demo.html")

NOTES = (
    "Demo data. Requests: real requests sent with curl through WireScope to local test servers on 127.0.0.1 "
    "(no real AI service; the agent-style bodies are made up). Packets: a hand-built pcap (TCP conversation with "
    "out-of-order, retransmitted and missing segments, plus a DNS query). Requests and packets are not linked here "
    "because the demo was recorded on a machine without capture permission."
)

AGENT_TURN_1 = {
    "model": "demo-model",
    "stream": True,
    "messages": [{"role": "user", "content": "Read src/main.cpp and explain the entry point."}],
    "metadata": {"session_id": "demo-session-1"},
}
AGENT_TURN_2 = {
    "model": "demo-model",
    "stream": True,
    "messages": [
        {"role": "user", "content": "Read src/main.cpp and explain the entry point."},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "read_file", "input": {"path": "src/main.cpp"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1",
                                      "content": "int main(int argc, char** argv) {\n    return run(argc, argv);\n}\n"}]},
    ],
    "metadata": {"session_id": "demo-session-2"},
}


def demo_pcap():
    """TCP conversation with capture problems + one DNS query, as classic pcap bytes."""
    C, S = (bytes([10, 0, 0, 1]), 50000), (bytes([10, 0, 0, 2]), 80)

    def frame(src, dst, proto, payload):
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src[0], dst[0])
        return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + payload

    def tcp(src, dst, seq, ack, flags, data=b""):
        return frame(src, dst, 6, struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 0x50, flags, 65535, 0, 0) + data)

    req1, req2 = b"GET /index.html HTTP/1.1\r\n", b"Host: example\r\n\r\n"
    r1, r2, r3 = b"HTTP/1.1 200 OK\r\n", b"Content-Length: 5\r\n\r\n", b"hello"
    cs, ss = 1000, 5000
    n_req, n_res = len(req1 + req2), len(r1 + r2 + r3)
    frames = [
        tcp(C, S, cs, 0, 0x02),                                      # SYN
        tcp(S, C, ss, cs + 1, 0x12),                                 # SYN+ACK
        tcp(C, S, cs + 1, ss + 1, 0x10),                             # ACK
        tcp(C, S, cs + 1 + len(req1), ss + 1, 0x18, req2),           # second half arrives first
        tcp(C, S, cs + 1, ss + 1, 0x18, req1),
        tcp(S, C, ss + 1, cs + 1 + n_req, 0x18, r1),
        tcp(S, C, ss + 1, cs + 1 + n_req, 0x18, r1),                 # retransmission
        tcp(S, C, ss + 1 + len(r1 + r2), cs + 1 + n_req, 0x18, r3),  # r2 never captured -> gap
        tcp(C, S, cs + 1 + n_req, ss + 1 + n_res, 0x11),             # FIN+ACK
        tcp(S, C, ss + 1 + n_res, cs + 2 + n_req, 0x11),             # FIN+ACK
        tcp(C, S, cs + 2 + n_req, ss + 2 + n_res, 0x10),             # ACK
    ]
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
    frames.append(frame((bytes([10, 0, 0, 1]), 53000), (bytes([10, 0, 0, 2]), 53), 17,
                        struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns))
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", 1767225600, i * 1500, len(fr), len(fr)) + fr
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="wirescope-demo-")
    procs = []
    try:
        it.make_certs(tmp)
        h1 = it.serve(http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler)).server_address[1]
        docs = f"{tmp}/h2docs"
        os.makedirs(docs)
        for name, body in {"models.json": {"models": ["demo-model"]}, "usage.json": {"requests": 2, "tokens": 512},
                           "status.json": {"ok": True}}.items():
            with open(f"{docs}/{name}", "w") as f:
                json.dump(body, f)
        h2 = it.free_port()
        procs.append(subprocess.Popen([it.NGHTTPD, "--address=127.0.0.1", f"--htdocs={docs}", "--trailer=x-demo-trailer: yes",
                                       str(h2), f"{tmp}/server.key", f"{tmp}/server.pem"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        engine = it.Engine(tmp)
        procs.append(engine.proc)
        proxy = it.free_port()
        engine.request("POST", "/api/proxy/start", {"port": proxy, "mitm": True})
        ca = f"{tmp}/data/root-ca.pem"

        for turn in (AGENT_TURN_1, AGENT_TURN_2):
            it.curl("-H", "Content-Type: application/json", "-d", json.dumps(turn), f"http://127.0.0.1:{h1}/demo/agent-turn", proxy=proxy)
        it.curl(f"http://127.0.0.1:{h1}/sse", proxy=proxy)
        it.curl("--compressed", f"http://127.0.0.1:{h1}/gzip", proxy=proxy)
        it.curl(f"http://127.0.0.1:{h1}/chunked", proxy=proxy)
        it.curl(f"http://127.0.0.1:{h1}/big", "-o", os.devnull, proxy=proxy)
        it.curl("--http2", "--cacert", ca, "-Z", *[f"https://localhost:{h2}/{n}" for n in ("models.json", "usage.json", "status.json")], proxy=proxy)
        it.curl(f"http://127.0.0.1:{it.free_port()}/refused", proxy=proxy)
        it.wait_settled(engine, 11)
        engine.request("POST", "/api/session", {"name": "WireScope demo", "client": "curl → local test servers",
                                                "action": "agent-style requests, SSE, gzip, chunked, 1.5 MiB body, HTTP/2 ×3, refused upstream",
                                                "notes": NOTES})
        engine.request("POST", "/api/proxy/stop", {})
        _, flows_archive = engine.request("GET", "/api/session/download", raw=True)
        flows_archive = json.loads(flows_archive)

        engine.request("POST", "/api/pcap/import", demo_pcap())
        _, packet_archive = engine.request("GET", "/api/session/download", raw=True)
        flows_archive["packets"] = json.loads(packet_archive)["packets"]
        status, r = engine.request("POST", "/api/session/import", flows_archive)
        if status != 200:
            raise RuntimeError(f"session import failed: {r}")

        status, html = engine.request("POST", "/api/report", {"redact": False}, raw=True)
        if status != 200:
            raise RuntimeError("report export failed")
        icon = ("<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' "
                "fill='none' stroke='%232169a5' stroke-width='2'%3E%3Ccircle cx='12' cy='12' r='8.5'/%3E%3Ccircle cx='12' cy='12' r='3.5'/%3E%3C/svg%3E\">")
        html = html.decode().replace("<title>WireScope · Capture report</title>", "<title>WireScope demo · offline inspector</title>" + icon, 1)
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as f:
            f.write(html)
        archive = json.loads(base64.b64decode(html.split("atob('")[1].split("')")[0]))
        print(f"{OUT}: {len(archive['flows'])} requests, {len(archive['packets'])} packets, {len(html) // 1024} KiB")
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
