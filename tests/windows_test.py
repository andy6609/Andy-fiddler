#!/usr/bin/env python3
"""Windows-only end-to-end checks: features that exist only in the Windows build.

    python tests/windows_test.py [path/to/build/Release]

1. Process attribution: a flow names the process that opened the proxy connection. The test starts
   curl.exe and python.exe children itself, so it knows the real PIDs and compares them with what
   WireScope recorded (pid, exe name/path, command line, parent = this test process).
2. System proxy: turning it on writes the WinINET setting (checked in the registry), a client that
   reads the system setting (Python urllib, no proxy argument) then goes through WireScope, and every
   way out restores the original value: turning it off, stopping the proxy, and the next start after
   a crash (TerminateProcess). This changes the current user's proxy setting for a few seconds, so it
   runs only when CI=true (GitHub Actions) or WIRESCOPE_TEST_SYSPROXY=1.
3. Unicode paths: --data pointing at a folder with Korean characters. argv arrives in the ANSI code page
   (cp1252 on the runner, cp949 on Korean Windows), so without re-reading the UTF-16 command line the
   characters become '?' and the CA would not land in that folder.

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


def registry():
    """The legacy Internet Settings values many clients read directly (Python urllib does)."""
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    out = {}
    for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
        try:
            out[name] = winreg.QueryValueEx(key, name)[0]
        except FileNotFoundError:
            out[name] = None
    winreg.CloseKey(key)
    return out


def same_registry(a, b):
    # An absent value and an empty/zero one mean the same to WinINET clients.
    return all((a.get(k) or "") == (b.get(k) or "") for k in a)


def same_settings(a, b):
    return all(a.get(k) == b.get(k) for k in ("flags", "server", "bypass", "autoConfigUrl"))


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


def sysproxy_checks(engine, tmp, h1, proxy):
    """Returns the engine still running at the end (the crash check replaces the original one)."""
    print("System proxy (WinINET per-connection options)")
    backup = f"{tmp}/data/system-proxy-backup.json"
    status, st = engine.request("GET", "/api/sysproxy")
    original, reg0 = st.get("current", {}), registry()
    print(f"  info original WinINET: {json.dumps(original)}")
    print(f"  info original registry: {json.dumps(reg0)}")
    check(st.get("supported") is True and not st.get("leftover"), "supported, no leftover backup at start")

    status, st = engine.request("POST", "/api/sysproxy", {"enable": True})
    cur = st.get("current", {})
    check(status == 200 and cur.get("enabled") and cur.get("server") == f"127.0.0.1:{proxy}" and st.get("ownedByWireScope"),
          f"enable: WinINET now reads back 127.0.0.1:{proxy} ({cur.get('server')})")
    check(os.path.exists(backup), "backup file written")
    reg = registry()
    print(f"  info registry while on: {json.dumps(reg)}")
    check(reg["ProxyEnable"] == 1 and reg["ProxyServer"] == f"127.0.0.1:{proxy}", "registry ProxyEnable=1 / ProxyServer reflect the change")

    # A client that is given no proxy at all, only the system setting: Python's default urllib opener.
    before = len(engine.flows())
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    code = ("import urllib.request,sys;sys.stderr.write(repr(urllib.request.getproxies()));"
            f"sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:{h1}/hello?who=system-proxy').read().decode())")
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = child.communicate(timeout=30)
    print(f"  info child urllib.getproxies(): {err.decode(errors='replace')[:300]}")
    flows = it.wait_settled(engine, before + 1)[before:]
    sp = [f for f in flows if f.get("path") == "/hello?who=system-proxy"]
    check(child.returncode == 0 and out == b"hello world" and len(sp) == 1, "python urllib with no proxy argument went through WireScope")
    check(sp and (sp[0].get("process") or {}).get("pid") == child.pid, "that flow is attributed to the python child")

    status, st = engine.request("POST", "/api/sysproxy", {"enable": False})
    check(status == 200 and same_settings(st.get("current", {}), original), f"disable: WinINET back to the original ({st.get('current')})")
    check(not os.path.exists(backup), "backup file removed after restore")
    check(same_registry(registry(), reg0), f"registry back to the original ({registry()})")

    engine.request("POST", "/api/sysproxy", {"enable": True})
    engine.request("POST", "/api/proxy/stop", {})
    st = engine.request("GET", "/api/sysproxy")[1]
    check(same_settings(st.get("current", {}), original) and not st.get("ownedByWireScope"), "stopping the proxy restores the system proxy first")

    # Crash: nothing runs in WireScope after TerminateProcess, so only the backup file can save the user.
    engine.request("POST", "/api/proxy/start", {"port": proxy, "mitm": True})
    engine.request("POST", "/api/sysproxy", {"enable": True})
    engine.proc.kill()
    engine.proc.wait(timeout=10)
    check(registry()["ProxyServer"] == f"127.0.0.1:{proxy}" and os.path.exists(backup),
          "after TerminateProcess the setting still points at the dead proxy and the backup file remains")
    engine = it.Engine(tmp)
    st = engine.request("GET", "/api/sysproxy")[1]
    check(st.get("leftover") is True and not st.get("ownedByWireScope"), "the next start reports the leftover backup")
    status, st = engine.request("POST", "/api/sysproxy", {"enable": False})
    check(status == 200 and same_settings(st.get("current", {}), original) and same_registry(registry(), reg0),
          "restoring from the leftover backup brings back the original setting")
    return engine


def unicode_path_checks(tmp):
    print("Unicode --data path (CommandLineToArgvW + u8path)")
    data = os.path.join(tmp, "한글 데이터 폴더")
    port = it.free_port()
    proc = subprocess.Popen([f"{it.BUILD}/WireScope{it.EXE}", "--no-open", "--port", str(port), "--data", data, "--web", f"{it.BUILD}/web"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        base = f"http://127.0.0.1:{port}"
        token = None
        for _ in range(100):
            try:
                token = json.load(it.urllib.request.urlopen(base + "/api/bootstrap"))["token"]
                break
            except OSError:
                time.sleep(0.05)
        check(token is not None, "engine started with a Korean --data path")
        if token is None:
            return
        req = it.urllib.request.Request(base + "/api/ca/create", data=b"{}", method="POST",
                                        headers={"X-WireScope-Token": token, "Content-Type": "application/json"})
        info = json.load(it.urllib.request.urlopen(req))
        print(f"  info CA path reported: {info.get('path')}")
        check("한글 데이터 폴더" in info.get("path", ""), "the engine reports the CA under the Korean folder name, not '?'")
        check(os.path.exists(os.path.join(data, "root-ca.pem")) and os.path.exists(os.path.join(data, "root-key.pem")),
              "root-ca.pem and root-key.pem exist in that exact folder")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def ensure_restored(tmp):
    """Safety net: never leave this machine's proxy pointing at a test port."""
    if os.path.exists(f"{tmp}/data/system-proxy-backup.json"):
        engine = it.Engine(tmp)
        try:
            print("  info safety restore:", engine.request("POST", "/api/sysproxy", {"enable": False})[0])
        finally:
            engine.proc.terminate()
            engine.proc.wait(timeout=10)


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
        unicode_path_checks(tmp)
        if os.environ.get("CI") == "true" or os.environ.get("WIRESCOPE_TEST_SYSPROXY") == "1":
            engine = sysproxy_checks(engine, tmp, h1, proxy)
            procs.append(engine.proc)
        else:
            print("  skip system proxy checks (they flip this user's proxy setting; set WIRESCOPE_TEST_SYSPROXY=1)")
        engine.request("POST", "/api/proxy/stop", {})
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        ensure_restored(tmp)
    print(f"{len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
