#!/usr/bin/env python3
"""Dry run of experiment 001 with the fake agent, whose behaviour is known exactly.

    python3 tests/experiment_dryrun_test.py [build-dir]

Checks that the kit (make_sandbox -> run_agent -> provenance) reports what the fake agent really sent, no more and no less.
"""
import http.server
import json
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import integration_test as it  # noqa: E402  (test HTTP server)

ROOT = os.path.dirname(HERE)
KIT = os.path.join(ROOT, "experiments", "001-agent-file-egress")
BUILD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build"))
failures = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        failures.append(label)


def main():
    tmp = tempfile.mkdtemp(prefix="ws-exp001-")
    sandbox, out = os.path.join(tmp, "sandbox"), os.path.join(tmp, "out")
    subprocess.run([sys.executable, os.path.join(KIT, "make_sandbox.py"), sandbox], check=True, capture_output=True)
    tokens = json.load(open(sandbox + ".canaries.json"))["tokens"]
    server = it.serve(http.server.ThreadingHTTPServer(("127.0.0.1", it.free_port()), it.Handler))
    env = dict(os.environ, FAKE_MODEL_URL=f"http://127.0.0.1:{server.server_address[1]}", PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run([sys.executable, os.path.join(KIT, "run_agent.py"), "--sandbox", sandbox, "--label", "fake-agent", "--out", out,
                          "--build", BUILD, "--task", "explain the config", "--", sys.executable, os.path.join(KIT, "fake_agent.py"), "{task}"],
                         env=env, capture_output=True, text=True)
    print("experiment 001 dry run")
    check(run.returncode == 0, f"run_agent finished {run.stderr[-300:]}")
    meta = json.load(open(os.path.join(out, "run.json")))
    check(meta["exit"] == 0 and meta["requests"] == 6 and meta["localFiles"] == 9, f"agent ran, 6 requests, 9 files registered ({meta})")
    r = json.loads(subprocess.run(["node", os.path.join(ROOT, "scripts", "provenance_cli.mjs"), os.path.join(out, "session.wscope"), "--json"],
                                  capture_output=True, text=True).stdout)
    cov = {c["fileName"]: c for c in r["coverage"]}
    check(cov["src/config.ts"]["ratio"] == 1, "config.ts: whole file seen")
    check(cov["src/main.cpp"]["ranges"] == [[15, 30]], f"main.cpp: exactly lines 15-30 ({cov['src/main.cpp']['ranges']})")
    design = cov["docs/design.md"]
    check(design["ranges"] and design["ranges"][0][0] == 1 and 0 < design["ratio"] < 1, f"design.md: only the start, output was cut ({design['ranges']})")
    check(cov[".env"]["matchedAnchors"] == 0, ".env: no lines seen")
    check(cov["assets/logo.png"]["ratio"] == 1, "logo.png: exact bytes in the multipart upload")
    seen = {x["token"] for x in r["canaries"]["sightings"]}
    check({tokens["config"], tokens["design"], tokens["logo"]} <= seen, "canaries of the files that were sent are seen")
    check(not {tokens["env"], tokens["main"], tokens["readme"], tokens["strings"], tokens["csv"]} & seen, "canaries of files (or lines) never sent are not seen")
    check(any(m["fileName"] == "src/config.ts" and m["flowId"] == 4 for m in r["matches"]), "earlier tool results resent in later turns are visible")
    summary = open(os.path.join(out, "summary.txt")).read()
    check("HOSTS" in summary and "COVERAGE" in summary and "NOT SEARCHED" in summary, "summary.txt has every section")
    print(f"{len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
