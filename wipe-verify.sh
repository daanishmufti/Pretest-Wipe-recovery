#!/usr/bin/env bash
# wipe-verify.sh — Pretest → Wipe → Recover → Verify harness.
#
# Flow:
#   0. GUARDS   refuse unless the target is safe to destroy (see lib/guards.sh)
#   1. SEED     write a known "pretest" signature across the device + known files
#   2. WIPE     overwrite with the chosen method (lib/wipe.sh)
#   3. RECOVER  raw signature scan + forensic carving (lib/recover.sh)
#   4. VERIFY   any surviving fragment  -> TEST FAILED (exit 1)
#               nothing recoverable      -> TEST PASSED (exit 0)
#
# Exit codes:  0 = PASS   1 = FAIL (data survived)   2 = guard abort / error
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/guards.sh
source "$SCRIPT_DIR/lib/guards.sh"
# shellcheck source=lib/seed.sh
source "$SCRIPT_DIR/lib/seed.sh"
# shellcheck source=lib/wipe.sh
source "$SCRIPT_DIR/lib/wipe.sh"
# shellcheck source=lib/recover.sh
source "$SCRIPT_DIR/lib/recover.sh"

# ------------------------------------------------------------------- defaults
DEVICE=""
METHOD="zero"
PASSES=3
ALLOWLIST="$SCRIPT_DIR/allowlist.conf"
REPORT_ROOT="$SCRIPT_DIR/reports"
DRY_RUN=0
FORCE=0
ASSUME_YES=0
ALLOW_INTERNAL=0
NO_CARVE=0
NO_FILES=0
SCAN_LIMIT=0            # 0 => scan whole device

usage() {
    cat <<EOF
Usage: sudo $0 --device <dev> [options]

Required:
  --device DEV         Target block device (must be in allowlist). e.g. /dev/sdb

Options:
  --method M           zero | random | dod | shred | blkdiscard   (default: zero)
  --passes N           passes for 'shred' (default: 3)
  --allowlist FILE     allowlist path (default: ./allowlist.conf)
  --report-dir DIR     where run reports are written (default: ./reports)
  --scan-limit BYTES   cap bytes scanned (0 = whole device, default)
  --no-files           skip the filesystem/known-file seed layer
  --no-carve           skip the forensic carving step (raw scan only)
  --dry-run            run guards + print actions, write nothing
  --yes                skip the typed serial confirmation (for automation)
  --allow-internal     permit INTERNAL/fixed disks (default: external/removable only)
  --force              override the 'no active holders' guard
  -h, --help           this help

Exit: 0 PASS, 1 FAIL (data survived), 2 guard abort / error
EOF
}

# ------------------------------------------------------------------- arg parse
while [[ $# -gt 0 ]]; do
    case "$1" in
        --device)     DEVICE="$2"; shift 2;;
        --method)     METHOD="$2"; shift 2;;
        --passes)     PASSES="$2"; shift 2;;
        --allowlist)  ALLOWLIST="$2"; shift 2;;
        --report-dir) REPORT_ROOT="$2"; shift 2;;
        --scan-limit) SCAN_LIMIT="$2"; shift 2;;
        --no-files)   NO_FILES=1; shift;;
        --no-carve)   NO_CARVE=1; shift;;
        --dry-run)    DRY_RUN=1; shift;;
        --yes)        ASSUME_YES=1; shift;;
        --allow-internal) ALLOW_INTERNAL=1; shift;;
        --force)      FORCE=1; shift;;
        -h|--help)    usage; exit 0;;
        *) echo "Unknown option: $1" >&2; usage; exit 2;;
    esac
done

[[ -z "$DEVICE" ]] && { echo "ERROR: --device is required." >&2; usage; exit 2; }

# ------------------------------------------------------------------- run setup
# Deterministic run id / timestamp without relying on wall clock inside libs.
RUN_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "run-$$")"
TOKEN="PRETEST-${RUN_ID}"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_DIR="$REPORT_ROOT/${NOW_ISO//:/-}_${RUN_ID:0:8}"
mkdir -p "$RUN_DIR"

DEV_JSON="$RUN_DIR/device.json"
PRE_JSON="$RUN_DIR/prewipe.json"
WIPE_JSON="$RUN_DIR/wipe.json"
RAW_JSON="$RUN_DIR/rawscan.json"
CARVE_JSON="$RUN_DIR/carve.json"
CARVED_DIR="$RUN_DIR/carved"
MANIFEST="$RUN_DIR/seed_manifest.json"
OUT_JSON="$RUN_DIR/report.json"
OUT_MD="$RUN_DIR/report.md"

echo "=============================================================" >&2
echo " Wipe-Verify harness   run=$RUN_ID" >&2
echo "   device=$DEVICE  method=$METHOD  dry_run=$DRY_RUN" >&2
echo "   report=$RUN_DIR" >&2
echo "=============================================================" >&2

# ------------------------------------------------------------------- Phase 0: guards
echo ">>> Phase 0: safety guards" >&2
if ! run_all_guards "$DEVICE" "$ALLOWLIST" "$FORCE" "$ASSUME_YES" "$ALLOW_INTERNAL"; then
    echo "ABORTED by guards." >&2
    exit 2
fi
guard_write_identity_json "$DEVICE" "$DEV_JSON"
SIZE=$(blockdev --getsize64 "$DEVICE" 2>/dev/null || echo 0)

if [[ "$SIZE" -le 0 ]]; then
    echo "ERROR: could not determine target size." >&2
    exit 2
fi
[[ "$SCAN_LIMIT" -gt 0 ]] && LIMIT="$SCAN_LIMIT" || LIMIT="$SIZE"

# ------------------------------------------------------------------- Phase 1: seed
echo ">>> Phase 1: seed pretest data" >&2
seed_raw_fill "$DEVICE" "$TOKEN" "$SIZE"
if [[ "$NO_FILES" == "0" ]]; then
    seed_files "$DEVICE" "$TOKEN" "$MANIFEST"
    # re-fill any filesystem metadata gaps so the raw pattern still dominates
else
    echo '{"files": []}' > "$MANIFEST"
fi
seed_sanity_scan "$DEVICE" "$TOKEN" "$PRE_JSON" "$LIMIT"

PRE_HITS=$(python3 -c "import json,sys;print(json.load(open('$PRE_JSON')).get('signature_hits',0))" 2>/dev/null || echo 0)
echo "[seed] pre-wipe signature hits: $PRE_HITS" >&2
if [[ "$DRY_RUN" == "0" && "$PRE_HITS" -eq 0 ]]; then
    echo "ERROR: seeding produced no detectable signature; test would be invalid." >&2
    # still emit a report with ERROR verdict
fi

# ------------------------------------------------------------------- Phase 2: wipe
echo ">>> Phase 2: wipe ($METHOD)" >&2
WSTART=$(date +%s)
if ! wipe_run "$METHOD" "$DEVICE" "$SIZE" "$PASSES" "$WIPE_JSON" 0 0; then
    echo "ERROR: wipe failed." >&2
    exit 2
fi
WEND=$(date +%s)
# rewrite wipe.json with real timing now that the pass(es) completed
_write_wipe_json "$WIPE_JSON" "$METHOD" "$PASSES" "$SIZE" "$WSTART" "$WEND"

# ------------------------------------------------------------------- Phase 3: recover
echo ">>> Phase 3: recover / detect" >&2
recover_raw_scan "$DEVICE" "$TOKEN" "$RAW_JSON" "$LIMIT"
if [[ "$NO_CARVE" == "0" ]]; then
    recover_carve "$DEVICE" "$TOKEN" "$CARVED_DIR" "$MANIFEST" "$CARVE_JSON"
else
    echo '{"files_scanned": 0, "carved_matches": [], "carver": "skipped"}' > "$CARVE_JSON"
fi

# ------------------------------------------------------------------- Phase 4: verify
echo ">>> Phase 4: verdict" >&2
python3 "$SCRIPT_DIR/scan.py" report \
    --run-id "$RUN_ID" --token "$TOKEN" \
    --device-json "$DEV_JSON" \
    --prewipe-json "$PRE_JSON" \
    --wipe-json "$WIPE_JSON" \
    --rawscan-json "$RAW_JSON" \
    --carve-json "$CARVE_JSON" \
    --out-json "$OUT_JSON" --out-md "$OUT_MD" \
    --now "$NOW_ISO"
VERDICT_CODE=$?

echo "-------------------------------------------------------------" >&2
cat "$OUT_MD" >&2 2>/dev/null || true
exit $VERDICT_CODE
