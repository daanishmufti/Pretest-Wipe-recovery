#!/usr/bin/env bash
# lib/wipe.sh — Phase 2: overwrite / sanitize the target.
# Sourced by wipe-verify.sh. Relies on: $DRY_RUN, $NOW_EPOCH (fixed clock helper).
#
# Methods:
#   zero        single pass of 0x00                  (NIST 800-88 "Clear")
#   random      single pass of random data
#   dod         3 passes: 0x00, 0xFF, random + verify (DoD 5220.22-M)
#   shred       delegate to shred -n <passes> -z
#   blkdiscard  delegate to blkdiscard (TRIM)

_dd_pass() {
    # _dd_pass <src> <dev> <size> <label>
    local src="$1" dev="$2" size="$3" label="$4"
    echo "[wipe] pass: $label -> $dev" >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "DRY-RUN: dd if=$src of=$dev bs=4M count(bytes)=$size" >&2
        return 0
    fi
    dd if="$src" of="$dev" bs=4M iflag=fullblock count=$(( (size + 4194303) / 4194304 )) \
        conv=notrunc status=progress 2>&1 | tail -n1 >&2
    sync
}

# Emit a wipe-result JSON fragment. Timing is passed in (epoch seconds) so the
# script stays deterministic and testable.
_write_wipe_json() {
    local out="$1" method="$2" passes="$3" bytes="$4" start="$5" end="$6"
    local dur tput
    dur=$(( end - start )); (( dur < 1 )) && dur=1
    tput=$(awk -v b="$bytes" -v d="$dur" 'BEGIN{printf "%.1f", (b/1048576)/d}')
    cat > "$out" <<EOF
{
  "method": "$method",
  "passes": $passes,
  "bytes": $bytes,
  "duration_s": $dur,
  "throughput_mb_s": $tput
}
EOF
}

# wipe_run <method> <dev> <size> <passes> <out_json> <start_epoch> <end_epoch>
wipe_run() {
    local method="$1" dev="$2" size="$3" passes="$4" out="$5" start="$6" end="$7"
    case "$method" in
        zero)
            _dd_pass /dev/zero "$dev" "$size" "zeros (NIST Clear)"
            passes=1
            ;;
        random)
            _dd_pass /dev/urandom "$dev" "$size" "random"
            passes=1
            ;;
        dod)
            _dd_pass /dev/zero "$dev" "$size" "1/3 zeros"
            _write_ff_pass "$dev" "$size"
            _dd_pass /dev/urandom "$dev" "$size" "3/3 random"
            passes=3
            ;;
        shred)
            echo "[wipe] delegating to shred -v -n $passes -z" >&2
            if [[ "$DRY_RUN" == "1" ]]; then
                echo "DRY-RUN: shred -v -n $passes -z $dev" >&2
            else
                shred -v -n "$passes" -z "$dev" >&2
            fi
            ;;
        blkdiscard)
            echo "[wipe] delegating to blkdiscard" >&2
            if [[ "$DRY_RUN" == "1" ]]; then
                echo "DRY-RUN: blkdiscard -f $dev" >&2
            else
                blkdiscard -f "$dev" >&2
            fi
            passes=1
            ;;
        *)
            echo "[wipe] unknown method: $method" >&2
            return 3
            ;;
    esac
    _write_wipe_json "$out" "$method" "$passes" "$size" "$start" "$end"
}

# 0xFF pass helper (no /dev/ones exists) — stream from tr.
_write_ff_pass() {
    local dev="$1" size="$2"
    echo "[wipe] pass: 2/3 ones (0xFF) -> $dev" >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "DRY-RUN: 0xFF fill of $size bytes -> $dev" >&2
        return 0
    fi
    tr '\0' '\377' < /dev/zero \
        | dd of="$dev" bs=4M iflag=fullblock count=$(( (size + 4194303) / 4194304 )) \
              conv=notrunc status=none
    sync
}
