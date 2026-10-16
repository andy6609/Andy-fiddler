#!/usr/bin/env python3
"""A stand-in "coding agent" for dry runs of experiment 001. It talks to a local test server, not a real service.

    FAKE_MODEL_URL=http://127.0.0.1:PORT python3 fake_agent.py

It behaves the way the experiment wants to tell apart, with a known ground truth:
  - reads src/config.ts completely and sends it as a numbered tool result
  - reads only lines 15-30 of src/main.cpp
  - reads docs/design.md but its tool output is cut at 2000 characters
  - never reads .env
  - uploads assets/logo.png as multipart/form-data
  - sends gzip-compressed telemetry that names files but carries no file content
Requests go through HTTP_PROXY like any client that honours proxy variables.
"""
import gzip
import json
import os
import sys
import urllib.request

BASE = os.environ["FAKE_MODEL_URL"].rstrip("/")


def read_numbered(path, first=None, last=None, limit=None):
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    first = first or 1
    last = last or len(lines)
    text = "\n".join(f"{n:>6}→{lines[n - 1]}" for n in range(first, min(last, len(lines)) + 1))
    if limit and len(text) > limit:
        text = text[:limit] + "\n... [output truncated]"
    return text


def post(path, body, headers):
    req = urllib.request.Request(BASE + path, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def turn(messages):
    return post("/v1/messages", json.dumps({"model": "fake-agent", "messages": messages}).encode(), {"Content-Type": "application/json"})


def main():
    task = sys.argv[1] if len(sys.argv) > 1 else "look around the repository"
    messages = [{"role": "user", "content": task}]
    turn(messages)
    for i, (path, kwargs) in enumerate([("src/config.ts", {}), ("src/main.cpp", {"first": 15, "last": 30}), ("docs/design.md", {"limit": 2000})]):
        messages.append({"role": "assistant", "content": [{"type": "tool_use", "id": f"call_{i}", "name": "read_file", "input": {"path": path, **kwargs}}]})
        messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": f"call_{i}", "content": read_numbered(path, **kwargs)}]})
        turn(messages)

    with open("assets/logo.png", "rb") as f:
        png = f.read()
    boundary = "fakeagentboundary42"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nattachment\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"logo.png\"\r\nContent-Type: image/png\r\n\r\n").encode() + png + f"\r\n--{boundary}--\r\n".encode()
    post("/v1/files", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    telemetry = gzip.compress(json.dumps({"event": "files_touched", "paths": ["src/config.ts", "src/main.cpp", "docs/design.md"]}).encode())
    post("/v1/telemetry", telemetry, {"Content-Type": "application/json", "Content-Encoding": "gzip"})
    print("fake agent done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
