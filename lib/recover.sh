#!/usr/bin/env bash
# lib/recover.sh — Phase 3: attempt recovery of the pretest data after the wipe.
# Two independent detectors:
#   1. raw signature scan of the whole device
#   2. forensic file carving (photorec / scalpel) + scan of carved output
# Sourced by wipe-verify.sh. Relies on: $SCRIPT_DIR, $DRY_RUN.

# Raw byte-level scan of the entire device for the run signature.
recover_raw_scan() {
    local dev="$1" token="$2" out="$3" limit="$4"
    echo "[recover] raw signature scan of $dev ..." >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo '{"signature_hits": 0, "bytes_scanned": 0, "offsets_sample": []}' > "$out"
        return 0
    fi
    python3 "$SCRIPT_DIR/scan.py" scan --token "$token" --path "$dev" \
        --limit "$limit" --json-out "$out"
}

# Forensic carving: run photorec (fallback scalpel) into $carved_dir, then scan
# every carved file for the signature and compare hashes against the seed manifest.
recover_carve() {
    local dev="$1" token="$2" carved_dir="$3" manifest="$4" out="$5"
    mkdir -p "$carved_dir"
    echo "[recover] forensic carving into $carved_dir ..." >&2

    if [[ "$DRY_RUN" == "1" ]]; then
        echo '{"files_scanned": 0, "carved_matches": []}' > "$out"
        return 0
    fi

    if command -v photorec >/dev/null 2>&1; then
        # non-interactive photorec: recover into carved_dir, then quit.
        photorec /d "$carved_dir/recup" /cmd "$dev" wholespace,everything,search \
            >/dev/null 2>&1 || echo "[recover] photorec returned non-zero (continuing)" >&2
    elif command -v scalpel >/dev/null 2>&1; then
        scalpel -o "$carved_dir/scalpel" "$dev" >/dev/null 2>&1 \
            || echo "[recover] scalpel returned non-zero (continuing)" >&2
    else
        echo "[recover] no carving tool (photorec/scalpel) installed — skipping carve step." >&2
        echo '{"files_scanned": 0, "carved_matches": [], "carver": "none"}' > "$out"
        return 0
    fi

    python3 "$SCRIPT_DIR/scan.py" scan-dir --token "$token" --dir "$carved_dir" \
        --seeded-manifest "$manifest" --json-out "$out"
}
