#!/usr/bin/env python3
"""Minimal HTTP/2-over-TLS file server for test hosts without nghttpd (Windows).

Takes the subset of nghttpd's command line that tests/integration_test.py and tests/lab_smoke.py use:

    python h2_server.py --address=127.0.0.1 --htdocs=DIR [--trailer="name: value"] PORT KEY CERT

GET and POST both answer with the file at the request path (a POST body is read and dropped, as
nghttpd does), 404 otherwise. Every response ends with the configured trailer in its own HEADERS
frame. Needs the 'h2' package (pip install h2).
"""
import os
import socket
import ssl
import sys
import threading

sys.dont_write_bytecode = True
import h2.config  # noqa: E402
import h2.connection  # noqa: E402
import h2.events  # noqa: E402


def parse(argv):
    opts, positional = {"address": "127.0.0.1", "htdocs": ".", "trailer": ""}, []
    for arg in argv:
        if arg.startswith("--") and "=" in arg:
            key, value = arg[2:].split("=", 1)
            opts[key] = value
        else:
            positional.append(arg)
    port, key, cert = positional
    return opts, int(port), key, cert


class Connection:
    def __init__(self, sock, docs, trailer):
        self.sock, self.docs, self.trailer = sock, os.path.realpath(docs), trailer
        self.conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        self.paths = {}     # stream id -> request path
        self.outgoing = {}  # stream id -> response bytes not yet sent (flow control)

    def file_for(self, path):
        name = os.path.realpath(os.path.join(self.docs, path.split("?", 1)[0].lstrip("/")))
        if name.startswith(self.docs + os.sep) and os.path.isfile(name):
            with open(name, "rb") as f:
                return f.read()
        return None

    def respond(self, stream_id):
        body = self.file_for(self.paths.pop(stream_id, "/"))
        status, body = (200, body) if body is not None else (404, b"not found")
        self.conn.send_headers(stream_id, [(":status", str(status)), ("content-length", str(len(body))),
                                           ("content-type", "application/json" if status == 200 else "text/plain")])
        self.outgoing[stream_id] = body
        self.flush()

    def flush(self):
        for stream_id in list(self.outgoing):
            body = self.outgoing[stream_id]
            while body:
                room = min(self.conn.local_flow_control_window(stream_id), self.conn.max_outbound_frame_size)
                if room <= 0:
                    break  # wait for WINDOW_UPDATE
                self.conn.send_data(stream_id, body[:room])
                body = body[room:]
            self.outgoing[stream_id] = body
            if not body:
                del self.outgoing[stream_id]
                if self.trailer:
                    name, value = self.trailer.split(":", 1)
                    self.conn.send_headers(stream_id, [(name.strip().lower(), value.strip())], end_stream=True)
                else:
                    self.conn.end_stream(stream_id)

    def run(self):
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())
        while True:
            data = self.sock.recv(65536)
            if not data:
                return
            for event in self.conn.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    self.paths[event.stream_id] = dict(event.headers).get(":path", "/")
                elif isinstance(event, h2.events.DataReceived):
                    self.conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    self.respond(event.stream_id)
                elif isinstance(event, h2.events.WindowUpdated):
                    self.flush()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    self.sock.sendall(self.conn.data_to_send())
                    return
            self.sock.sendall(self.conn.data_to_send())


def handle(raw, ctx, docs, trailer):
    try:
        with ctx.wrap_socket(raw, server_side=True) as sock:
            Connection(sock, docs, trailer).run()
    except (OSError, ssl.SSLError):
        pass  # client went away; the tests judge the result from the client side


def main():
    opts, port, key, cert = parse(sys.argv[1:])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    listener = socket.create_server((opts["address"], port))
    while True:
        raw, _ = listener.accept()
        threading.Thread(target=handle, args=(raw, ctx, opts["htdocs"], opts["trailer"]), daemon=True).start()


if __name__ == "__main__":
    main()
