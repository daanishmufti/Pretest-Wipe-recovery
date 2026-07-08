#!/usr/bin/env python3
"""
ui/server.py — tiny local web UI for the wipe-verify harness.

Zero external dependencies (Python stdlib only). Binds to 127.0.0.1 so it is not
reachable off-host. It shells out to ../wipe-verify.sh, so to actually wipe a real
device you must launch it with root:

    sudo python3 ui/server.py          # then open http://127.0.0.1:8770

Endpoints:
    GET  /                      the single-page UI
    GET  /api/devices           allowlisted devices + lsblk identity
    GET  /api/reports           recent run reports (verdict summaries)
    GET  /api/run?...           run the harness, stream output as Server-Sent Events

Safety: the run endpoint requires a `confirm` param equal to the device serial
(the same check guard_typed_confirmation does at the CLI). Only when it matches
does the server invoke the harness with --yes. All other guards (allowlist, mount,
system-disk, holders) still run inside wipe-verify.sh.
"""

import html
import json
import os
import shlex
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HARNESS = os.path.join(ROOT, "wipe-verify.sh")
ALLOWLIST = os.path.join(ROOT, "allowlist.conf")
REPORTS = os.path.join(ROOT, "reports")
HOST, PORT = "127.0.0.1", 8770

METHODS = ["zero", "random", "dod", "shred", "blkdiscard"]


# --------------------------------------------------------------------- helpers
def _canon(path):
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def _lsblk(dev, col):
    try:
        out = subprocess.run(["lsblk", "-dn", "-o", col, dev],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip()
    except Exception:
        return ""


def _classify(canon):
    """Return 'loop' | 'external' | 'internal' | 'unknown' — mirrors guard_external_only."""
    base = os.path.basename(canon)
    if base.startswith("loop"):
        return "loop"
    try:
        with open(f"/sys/block/{base}/removable") as f:
            removable = f.read().strip()
    except OSError:
        removable = ""
    hotplug = _lsblk(canon, "HOTPLUG")
    tran = _lsblk(canon, "TRAN")
    if removable == "1" or hotplug == "1" or tran == "usb":
        return "external"
    if tran or removable == "0":
        return "internal"
    return "unknown"


def device_info(dev):
    canon = _canon(dev)
    exists = os.path.exists(canon)
    serial = _lsblk(canon, "SERIAL") if exists else ""
    if not serial:
        serial = os.path.basename(canon)   # loop devices have no serial
    kind = _classify(canon) if exists else "unknown"
    return {
        "path": dev,
        "canonical": canon,
        "exists": exists,
        "is_block": os.path.exists(canon) and _is_block(canon),
        "model": _lsblk(canon, "MODEL") if exists else "",
        "size": _lsblk(canon, "SIZE") if exists else "",
        "serial": serial,
        "kind": kind,   # loop | external | internal | unknown
    }


def _is_block(path):
    try:
        import stat
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def read_allowlist():
    devs = []
    if not os.path.exists(ALLOWLIST):
        return devs
    with open(ALLOWLIST) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                devs.append(device_info(line))
    return devs


def recent_reports(limit=10):
    out = []
    if not os.path.isdir(REPORTS):
        return out
    dirs = sorted((d for d in os.listdir(REPORTS)
                   if os.path.isdir(os.path.join(REPORTS, d))), reverse=True)
    for d in dirs[:limit]:
        rj = os.path.join(REPORTS, d, "report.json")
        if os.path.exists(rj):
            try:
                with open(rj) as f:
                    r = json.load(f)
                out.append({
                    "dir": d,
                    "verdict": r.get("verdict"),
                    "reason": r.get("verdict_reason"),
                    "device": r.get("device", {}).get("path"),
                    "method": r.get("wipe", {}).get("method"),
                    "generated": r.get("generated_utc"),
                })
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/devices":
            self._send(200, {"devices": read_allowlist(),
                             "methods": METHODS, "is_root": os.geteuid() == 0})
        elif path == "/api/reports":
            self._send(200, {"reports": recent_reports()})
        elif path == "/api/run":
            self._run_stream(qs)
        else:
            self._send(404, {"error": "not found"})

    # ------------------------------------------------------------- run + stream
    def _run_stream(self, qs):
        def get(k, d=""):
            return qs.get(k, [d])[0]

        device = get("device")
        method = get("method", "zero")
        confirm = get("confirm")
        dry = get("dry") == "1"
        no_carve = get("no_carve") == "1"
        no_files = get("no_files") == "1"
        allow_internal = get("allow_internal") == "1"

        # validate against allowlist + serial confirmation (mirrors the CLI guard)
        allow = {d["path"]: d for d in read_allowlist()}
        info = allow.get(device)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def emit(event, data):
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
            try:
                self.wfile.write(payload.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

        if info is None:
            emit("log", f"[ui] '{device}' is not in the allowlist — refusing.")
            emit("done", {"exit": 2, "verdict": "ERROR"})
            return
        if method not in METHODS:
            emit("log", f"[ui] invalid method '{method}'.")
            emit("done", {"exit": 2, "verdict": "ERROR"})
            return
        if not dry and confirm != info["serial"]:
            emit("log", "[ui] serial confirmation did not match — refusing. "
                        f"(expected the serial shown for {device})")
            emit("done", {"exit": 2, "verdict": "ERROR"})
            return

        cmd = ["bash", HARNESS, "--device", device, "--method", method, "--yes"]
        if dry:
            cmd.append("--dry-run")
        if no_carve:
            cmd.append("--no-carve")
        if no_files:
            cmd.append("--no-files")
        if allow_internal:
            cmd.append("--allow-internal")

        emit("log", f"[ui] $ {' '.join(shlex.quote(c) for c in cmd)}")
        if os.geteuid() != 0 and not dry:
            emit("log", "[ui] WARNING: server not running as root; the harness will "
                        "abort at the root guard. Restart with: sudo python3 ui/server.py")

        try:
            proc = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
        except Exception as e:
            emit("log", f"[ui] failed to start harness: {e}")
            emit("done", {"exit": 2, "verdict": "ERROR"})
            return

        try:
            for line in iter(proc.stdout.readline, ""):
                emit("log", line.rstrip("\n"))
            proc.wait()
        except (BrokenPipeError, ConnectionResetError):
            proc.kill()
            return

        # find the freshest report and return its verdict
        result = {"exit": proc.returncode, "verdict": None, "report": None}
        rep = recent_reports(1)
        if rep:
            result["verdict"] = rep[0]["verdict"]
            result["report"] = rep[0]
        emit("done", result)


PAGE = None  # populated below from index.html


def main():
    global PAGE
    with open(os.path.join(HERE, "index.html")) as f:
        PAGE = f.read()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    root_note = "" if os.geteuid() == 0 else "  (NOT root — real wipes will be refused; use sudo)"
    print(f"wipe-verify UI  ->  http://{HOST}:{PORT}{root_note}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", file=sys.stderr)


if __name__ == "__main__":
    main()
