# Pretest → Wipe → Recover → Verify Harness

A tool that **proves a disk wipe actually worked**. It:

1. **Seeds** the target with a known, detectable "pretest" signature (magic marker + a
   per-run unique token) across every sector, plus a layer of known files.
2. **Wipes** the target with the chosen method.
3. **Recovers** — raw signature scan of the whole device **and** forensic file carving
   (photorec/scalpel) of the wiped device.
4. **Verifies**:
   - **any surviving fragment → `TEST FAILED` (exit 1)**
   - **nothing recoverable → `TEST PASSED` (exit 0)**

This maps onto **NIST SP 800-88 Rev.1** (Clear / Purge / Destroy). It is a
media-sanitization *validation* tool.

> ⚠️ **This destroys data by design.** It only operates on **real block devices** listed
> in `allowlist.conf`, refuses mounted/system disks, and (by default) refuses internal
> fixed disks — only external/removable drives are permitted.

## Layout

| File | Role |
|------|------|
| `wipe-verify.sh`  | **Main harness** — orchestrates all phases, decides pass/fail |
| `lib/guards.sh`   | Safety guards (root, allowlist, mount/system-disk/external/holder, typed confirm) |
| `lib/seed.sh`     | Phase 1 — seed pretest data |
| `lib/wipe.sh`     | Phase 2 — wipe methods |
| `lib/recover.sh`  | Phase 3 — raw scan + forensic carving |
| `scan.py`         | Pattern generation, signature scanning, and the JSON/Markdown report |
| `ui/`             | Optional local web UI (`server.py` + `index.html`) |
| `allowlist.example.conf` | Template for the permitted-device allowlist |
| `reports/`        | Timestamped run reports (`report.json` + `report.md`) |

## Dependencies

`bash`, `python3`, `dd`, `lsblk`, `findmnt`, `blockdev`, `sha256sum`, and (per method/step)
`shred`, `blkdiscard`, `mkfs.ext4`, `testdisk`/`photorec`, optional `scalpel`.

```bash
sudo apt install coreutils util-linux testdisk   # photorec ships in testdisk
```

## Usage

```bash
# 1. identify the target and its stable path (confirm it is NOT your system disk)
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,MOUNTPOINT
ls -l /dev/disk/by-id/

# 2. allowlist it (by-id path preferred over /dev/sdX)
cp allowlist.example.conf allowlist.conf
echo /dev/disk/by-id/usb-YOUR_DRIVE_SERIAL >> allowlist.conf

# 3. run (you will be shown the model/serial and asked to retype the serial to confirm)
sudo ./wipe-verify.sh --device /dev/disk/by-id/usb-YOUR_DRIVE_SERIAL --method zero
echo "exit=$?"        # 0 PASS · 1 FAIL (data survived) · 2 guard abort

# 4. read the result
cat reports/*/report.md
```

| Method | Description |
|--------|-------------|
| `zero`       | single pass of `0x00` — NIST 800-88 **Clear** |
| `random`     | single pass of random data |
| `dod`        | 3 passes: `0x00`, `0xFF`, random — DoD 5220.22-M |
| `shred`      | delegate to `shred -n <passes> -z` |
| `blkdiscard` | delegate to `blkdiscard` (TRIM, SSD) |

Useful flags: `--dry-run` (guards + print actions, no writes), `--yes` (skip typed
confirm for automation), `--no-carve` (raw scan only), `--no-files` (skip file layer),
`--scan-limit BYTES`, `--allow-internal` (permit internal disks), `--force` (override
the holder guard). See `--help`.

## Safety guards

`wipe-verify.sh` refuses (exit 2) unless **all** pass: running as root; target is a block
device; target is in `allowlist.conf`; target and its partitions are unmounted; target is
not the disk backing `/`, `/boot`, or swap; target is external/removable (not an internal
fixed disk — override with `--allow-internal`); no active LVM/RAID/crypt holders (override
with `--force`); and you retype the device serial to confirm.

## Web UI (optional)

```bash
sudo python3 ui/server.py          # then open http://127.0.0.1:8770
```

Bound to `127.0.0.1`, stdlib-only. Lists allowlisted devices (tagged
`external`/`internal`), lets you pick method + flags, streams the harness output live, and
shows the PASS/FAIL verdict and run history. It enforces the same serial confirmation
before arming a run.

## Verdict logic

`FAIL` if post-wipe raw signature hits > 0 **or** any carved file contains the token /
matches a seeded file's hash. `PASS` only if both detectors come back empty. If the
pre-wipe sanity scan finds nothing, the run is `ERROR` (exit 2) — the test would be
meaningless. Each run writes `reports/<timestamp>_<runid>/report.json` and `report.md`.
