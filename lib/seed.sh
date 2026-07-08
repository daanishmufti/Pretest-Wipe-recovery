#!/usr/bin/env bash
# lib/seed.sh — Phase 1: write known "pretest" data onto the target.
# Sourced by wipe-verify.sh. Relies on: $SCRIPT_DIR, $DRY_RUN, run() helper.

# Fill the entire device with the repeating signature pattern.
seed_raw_fill() {
    local dev="$1" token="$2" size="$3"
    echo "[seed] raw-filling $dev ($size bytes) with signature pattern..." >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "DRY-RUN: python3 scan.py gen --token $token --size $size | dd of=$dev" >&2
        return 0
    fi
    python3 "$SCRIPT_DIR/scan.py" gen --token "$token" --size "$size" \
        | dd of="$dev" bs=4M iflag=fullblock conv=notrunc status=progress 2>&1 | tail -n1 >&2
    sync
}

# Optional realistic-file layer: make a filesystem, drop known files (each embedding
# the token), record their sha256 into a manifest for later carving comparison.
seed_files() {
    local dev="$1" token="$2" manifest="$3" fstype="${4:-ext4}"
    local mnt seededdir f
    mnt=$(mktemp -d)
    echo "[seed] creating $fstype + known files on $dev ..." >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "DRY-RUN: mkfs.$fstype $dev; mount; write known files; record sha256" >&2
        echo '{"files": []}' > "$manifest"
        rmdir "$mnt"
        return 0
    fi

    if ! mkfs -t "$fstype" -q "$dev" 2>/dev/null; then
        echo "[seed] mkfs.$fstype failed (device too small?), skipping file layer." >&2
        echo '{"files": []}' > "$manifest"
        rmdir "$mnt"
        return 0
    fi
    mount "$dev" "$mnt"

    local entries=() name path magic
    # a few realistic file headers, each with the token embedded in the body
    declare -A HEADERS=(
        [known.txt]=""
        [known.jpg]=$'\xff\xd8\xff\xe0\x00\x10JFIF'
        [known.pdf]="%PDF-1.7"
        [known.zip]=$'PK\x03\x04'
    )
    for name in "${!HEADERS[@]}"; do
        path="$mnt/$name"
        magic="${HEADERS[$name]}"
        { printf '%b' "$magic"
          printf '\n~=PRETEST-MAGIC=~%s file=%s\n' "$token" "$name"
          head -c 4096 /dev/zero | tr '\0' 'A'
        } > "$path"
        local sum
        sum=$(sha256sum "$path" | awk '{print $1}')
        entries+=("{\"name\": \"$name\", \"sha256\": \"$sum\"}")
    done

    umount "$mnt"
    rmdir "$mnt"

    { echo '{ "files": ['
      local IFS=,; echo "${entries[*]}"
      echo '] }'
    } > "$manifest"
    echo "[seed] wrote ${#entries[@]} known files; manifest -> $manifest" >&2
    sync
}

# Confirm the seed is actually detectable before we wipe (else the test is meaningless).
seed_sanity_scan() {
    local dev="$1" token="$2" out="$3" limit="$4"
    echo "[seed] pre-wipe sanity scan..." >&2
    if [[ "$DRY_RUN" == "1" ]]; then
        echo '{"signature_hits": 1, "bytes_scanned": 0, "offsets_sample": [0]}' > "$out"
        return 0
    fi
    python3 "$SCRIPT_DIR/scan.py" scan --token "$token" --path "$dev" \
        --limit "$limit" --json-out "$out"
}
