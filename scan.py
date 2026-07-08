#!/usr/bin/env python3
"""
scan.py — pattern generation, detection, and reporting for the wipe-verify harness.

Subcommands:
  gen       Stream a repeating pretest pattern to stdout (piped into dd).
  scan      Scan a block device / file for the pretest signature; report count + offsets.
  scan-dir  Scan every file in a directory (photorec/scalpel output) for the signature.
  report    Combine phase results into report.json + report.md and decide PASS/FAIL.

The detection unit ("needle") is:  MAGIC_PREFIX || token
where the token is unique per run, so we only ever match data seeded by *this* run.
The generated pattern additionally appends an 8-byte block counter after the needle
so seeded content looks structured (and is distinguishable) on disk.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone

MAGIC_PREFIX = b"~=PRETEST-MAGIC=~"  # 17 bytes, rare/greppable
READ_CHUNK = 4 * 1024 * 1024         # 4 MiB streaming reads
MAX_OFFSETS = 32                     # cap recorded offsets to keep reports small


def needle(token: str) -> bytes:
    return MAGIC_PREFIX + token.encode("ascii", "strict")


# --------------------------------------------------------------------------- gen
def cmd_gen(args) -> int:
    """Write `size` bytes of the repeating pattern to stdout (or exactly one full
    device's worth). The pattern block = needle || 8-byte big-endian counter,
    padded to `block` bytes so every sector carries a locatable token."""
    n = needle(args.token)
    block_size = max(args.block, len(n) + 8)
    remaining = args.size
    out = sys.stdout.buffer
    counter = 0
    while remaining > 0:
        body = n + struct.pack(">Q", counter)
        # pad the block out to block_size with a repeating filler
        pad = block_size - len(body)
        block = body + (b"\xa5" * pad)
        if len(block) > remaining:
            block = block[:remaining]
        out.write(block)
        remaining -= len(block)
        counter += 1
    out.flush()
    return 0


# -------------------------------------------------------------------------- scan
def _scan_stream(fh, needle_bytes, byte_limit=None):
    """Count non-overlapping occurrences of needle_bytes in a stream, recording
    up to MAX_OFFSETS absolute byte offsets. Handles chunk-boundary matches by
    carrying an overlap tail of len(needle)-1 bytes."""
    count = 0
    offsets = []
    overlap = b""
    base = 0            # absolute offset of the start of `overlap`
    read_total = 0
    tail = len(needle_bytes) - 1
    while True:
        to_read = READ_CHUNK
        if byte_limit is not None:
            if read_total >= byte_limit:
                break
            to_read = min(to_read, byte_limit - read_total)
        chunk = fh.read(to_read)
        if not chunk:
            break
        read_total += len(chunk)
        buf = overlap + chunk
        start = 0
        while True:
            idx = buf.find(needle_bytes, start)
            if idx == -1:
                break
            count += 1
            if len(offsets) < MAX_OFFSETS:
                offsets.append(base + idx)
            start = idx + len(needle_bytes)
        # preserve tail for boundary-spanning matches
        keep = buf[len(buf) - tail:] if tail > 0 else b""
        base += len(buf) - len(keep)
        overlap = keep
    return count, offsets, read_total


def cmd_scan(args) -> int:
    n = needle(args.token)
    with open(args.path, "rb", buffering=0) as fh:
        count, offsets, scanned = _scan_stream(fh, n, args.limit)
    result = {
        "path": args.path,
        "bytes_scanned": scanned,
        "signature_hits": count,
        "offsets_sample": offsets,
    }
    _emit(args.json_out, result)
    print(f"[scan] {args.path}: {count} hit(s) in {scanned} bytes", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------- scan-dir
def cmd_scan_dir(args) -> int:
    n = needle(args.token)
    seeded = {}
    if args.seeded_manifest and os.path.exists(args.seeded_manifest):
        with open(args.seeded_manifest) as f:
            seeded = {e["sha256"]: e["name"] for e in json.load(f).get("files", [])}
    matches = []
    files_scanned = 0
    for root, _dirs, files in os.walk(args.dir):
        for name in files:
            fp = os.path.join(root, name)
            try:
                with open(fp, "rb", buffering=0) as fh:
                    count, offsets, _ = _scan_stream(fh, n)
                    fh.seek(0)
                    digest = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                continue
            files_scanned += 1
            recovered_name = seeded.get(digest)
            if count > 0 or recovered_name:
                matches.append({
                    "file": fp,
                    "signature_hits": count,
                    "sha256": digest,
                    "matches_seeded_file": recovered_name,
                })
    result = {
        "carved_dir": args.dir,
        "files_scanned": files_scanned,
        "carved_matches": matches,
    }
    _emit(args.json_out, result)
    print(f"[scan-dir] {args.dir}: {len(matches)} matching file(s) of "
          f"{files_scanned} carved", file=sys.stderr)
    return 0


# ------------------------------------------------------------------------ report
def cmd_report(args) -> int:
    """Merge phase JSON fragments and decide the verdict."""
    def load(p):
        if p and os.path.exists(p):
            with open(p) as f:
                return json.load(f)
        return {}

    device = load(args.device_json)
    pre = load(args.prewipe_json)
    wipe = load(args.wipe_json)
    raw = load(args.rawscan_json)
    carve = load(args.carve_json)

    raw_hits = raw.get("signature_hits", 0)
    carved_matches = carve.get("carved_matches", [])
    pre_hits = pre.get("signature_hits", 0)

    seeding_ok = pre_hits > 0
    survived = raw_hits > 0 or len(carved_matches) > 0
    if not seeding_ok:
        verdict, exit_code = "ERROR", 2
        verdict_reason = "Pre-wipe sanity scan found no seeded signature; test is invalid."
    elif survived:
        verdict, exit_code = "FAIL", 1
        verdict_reason = (f"Pretest data survived: {raw_hits} raw signature hit(s), "
                          f"{len(carved_matches)} carved file match(es).")
    else:
        verdict, exit_code = "PASS", 0
        verdict_reason = "No pretest signature or recoverable file found after wipe."

    report = {
        "generated_utc": args.now or datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "token": args.token,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "device": device,
        "wipe": wipe,
        "pre_wipe_sanity": pre,
        "post_wipe_raw_scan": raw,
        "forensic_carving": carve,
    }

    out_dir = os.path.dirname(os.path.abspath(args.out_json))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out_json, "w") as f:
        json.dump(report, f, indent=2)
    with open(args.out_md, "w") as f:
        f.write(_render_md(report))

    print(f"\n=== VERDICT: {verdict} ===\n{verdict_reason}", file=sys.stderr)
    print(f"Report: {args.out_json}", file=sys.stderr)
    return exit_code


def _render_md(r) -> str:
    d = r.get("device", {})
    w = r.get("wipe", {})
    raw = r.get("post_wipe_raw_scan", {})
    carve = r.get("forensic_carving", {})
    badge = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "ERROR": "⚠️ ERROR"}.get(r["verdict"], r["verdict"])
    lines = [
        f"# Wipe Verification Report — {badge}",
        "",
        f"- **Generated:** {r.get('generated_utc')}",
        f"- **Run ID:** `{r.get('run_id')}`",
        f"- **Verdict:** **{r['verdict']}** — {r['verdict_reason']}",
        "",
        "## Device",
        f"- Path: `{d.get('path','?')}`",
        f"- Model: {d.get('model','?')}",
        f"- Serial: {d.get('serial','?')}",
        f"- Size: {d.get('size_bytes','?')} bytes",
        "",
        "## Wipe",
        f"- Method: `{w.get('method','?')}`  Passes: {w.get('passes','?')}",
        f"- Duration: {w.get('duration_s','?')} s  Throughput: {w.get('throughput_mb_s','?')} MB/s",
        "",
        "## Detection",
        f"- Pre-wipe signature hits (sanity): {r.get('pre_wipe_sanity',{}).get('signature_hits','?')}",
        f"- **Post-wipe raw signature hits: {raw.get('signature_hits','?')}**",
        f"- Raw hit offsets (sample): {raw.get('offsets_sample', [])}",
        f"- Carved files scanned: {carve.get('files_scanned','?')}",
        f"- **Carved file matches: {len(carve.get('carved_matches', []))}**",
    ]
    for m in carve.get("carved_matches", []):
        lines.append(f"    - `{m['file']}` hits={m['signature_hits']} "
                     f"seeded_match={m.get('matches_seeded_file')}")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------------- utils
def _emit(path, obj):
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
    else:
        json.dump(obj, sys.stdout, indent=2)
        print()


def main() -> int:
    p = argparse.ArgumentParser(description="Wipe-verify pattern/scan/report tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="stream repeating pattern to stdout")
    g.add_argument("--token", required=True)
    g.add_argument("--size", type=int, required=True, help="bytes to emit")
    g.add_argument("--block", type=int, default=512, help="pattern block size")
    g.set_defaults(func=cmd_gen)

    s = sub.add_parser("scan", help="scan a device/file for the signature")
    s.add_argument("--token", required=True)
    s.add_argument("--path", required=True)
    s.add_argument("--limit", type=int, default=None, help="max bytes to scan")
    s.add_argument("--json-out", default=None)
    s.set_defaults(func=cmd_scan)

    sd = sub.add_parser("scan-dir", help="scan carved files for the signature")
    sd.add_argument("--token", required=True)
    sd.add_argument("--dir", required=True)
    sd.add_argument("--seeded-manifest", default=None)
    sd.add_argument("--json-out", default=None)
    sd.set_defaults(func=cmd_scan_dir)

    r = sub.add_parser("report", help="merge results and decide verdict")
    r.add_argument("--run-id", required=True)
    r.add_argument("--token", required=True)
    r.add_argument("--device-json", default=None)
    r.add_argument("--prewipe-json", default=None)
    r.add_argument("--wipe-json", default=None)
    r.add_argument("--rawscan-json", default=None)
    r.add_argument("--carve-json", default=None)
    r.add_argument("--out-json", required=True)
    r.add_argument("--out-md", required=True)
    r.add_argument("--now", default=None, help="ISO timestamp override")
    r.set_defaults(func=cmd_report)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
