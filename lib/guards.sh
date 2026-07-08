#!/usr/bin/env bash
# lib/guards.sh — device safety guards. Sourced by wipe-verify.sh.
# Every function returns non-zero (and the harness aborts with exit 2) on failure.

# Resolve the whole-disk device that backs a mountpoint, e.g. / -> /dev/sda
_disk_backing() {
    local mnt="$1" src part
    src=$(findmnt -n -o SOURCE --target "$mnt" 2>/dev/null) || return 0
    [[ -z "$src" ]] && return 0
    # strip partition to parent disk (handles sda1->sda, nvme0n1p2->nvme0n1)
    part=$(lsblk -n -o PKNAME "$src" 2>/dev/null | head -n1)
    [[ -n "$part" ]] && echo "/dev/$part" || echo "$src"
}

# Canonicalize a device path (resolve /dev/disk/by-id symlinks)
_canon() { readlink -f "$1" 2>/dev/null || echo "$1"; }

guard_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "GUARD FAIL: must run as root to access block devices." >&2
        return 1
    fi
}

guard_is_block_device() {
    local dev="$1"
    if [[ ! -b "$dev" ]]; then
        echo "GUARD FAIL: '$dev' is not a block device." >&2
        return 1
    fi
}

# Target must appear in the allowlist file (matched after canonicalization).
guard_allowlist() {
    local dev="$1" allowlist="$2" want line entry
    want=$(_canon "$dev")
    if [[ ! -f "$allowlist" ]]; then
        echo "GUARD FAIL: allowlist '$allowlist' not found." >&2
        return 1
    fi
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        entry=$(_canon "$line")
        if [[ "$entry" == "$want" ]]; then
            return 0
        fi
    done < "$allowlist"
    echo "GUARD FAIL: '$dev' ($want) is not in allowlist '$allowlist'." >&2
    return 1
}

# Refuse if the device or any of its partitions is mounted.
guard_not_mounted() {
    local dev="$1" canon holders
    canon=$(_canon "$dev")
    if findmnt -n -S "$canon" >/dev/null 2>&1; then
        echo "GUARD FAIL: '$dev' is mounted." >&2
        return 1
    fi
    # check child partitions
    while IFS= read -r child; do
        [[ -z "$child" ]] && continue
        if findmnt -n -S "/dev/$child" >/dev/null 2>&1; then
            echo "GUARD FAIL: partition '/dev/$child' of '$dev' is mounted." >&2
            return 1
        fi
    done < <(lsblk -n -o NAME "$canon" 2>/dev/null | tail -n +2)
}

# Refuse if target is the disk backing /, /boot, or active swap.
guard_not_system_disk() {
    local dev="$1" canon d
    canon=$(_canon "$dev")
    for mnt in / /boot /boot/efi; do
        d=$(_disk_backing "$mnt")
        [[ -n "$d" ]] || continue
        if [[ "$(_canon "$d")" == "$canon" ]]; then
            echo "GUARD FAIL: '$dev' backs system mount '$mnt'. Refusing." >&2
            return 1
        fi
    done
    # active swap devices
    while read -r sdev _; do
        [[ "$sdev" == "Filename" || -z "$sdev" ]] && continue
        [[ -b "$sdev" ]] || continue
        local sparent
        sparent=$(lsblk -n -o PKNAME "$sdev" 2>/dev/null | head -n1)
        [[ -n "$sparent" ]] && sdev="/dev/$sparent"
        if [[ "$(_canon "$sdev")" == "$canon" ]]; then
            echo "GUARD FAIL: '$dev' hosts active swap. Refusing." >&2
            return 1
        fi
    done < <(cat /proc/swaps 2>/dev/null)
}

# Refuse if device has holders (LVM/RAID/crypt) unless --force.
guard_no_holders() {
    local dev="$1" force="$2" canon base holders
    canon=$(_canon "$dev")
    base=$(basename "$canon")
    if [[ -d "/sys/block/$base/holders" ]]; then
        holders=$(ls -A "/sys/block/$base/holders" 2>/dev/null)
        if [[ -n "$holders" && "$force" != "1" ]]; then
            echo "GUARD FAIL: '$dev' has active holders ($holders). Use --force to override." >&2
            return 1
        fi
    fi
}

# Refuse INTERNAL / fixed disks. Only external / removable drives (USB sticks,
# external SSDs) are permitted. This protects the machine's own built-in storage
# even if it were mistakenly added to the allowlist.
# Overridable with --allow-internal for advanced/deliberate use.
guard_external_only() {
    local dev="$1" allow_internal="$2" canon base removable hotplug tran
    canon=$(_canon "$dev")
    base=$(basename "$canon")

    if [[ "$allow_internal" == "1" ]]; then
        echo "[guard] --allow-internal set: skipping external-only check." >&2
        return 0
    fi

    # signals that a device is external/removable
    removable=$(cat "/sys/block/$base/removable" 2>/dev/null)
    hotplug=$(lsblk -dn -o HOTPLUG "$canon" 2>/dev/null | xargs)
    tran=$(lsblk -dn -o TRAN "$canon" 2>/dev/null | xargs)

    if [[ "$removable" == "1" || "$hotplug" == "1" || "$tran" == "usb" ]]; then
        return 0
    fi

    echo "GUARD FAIL: '$dev' looks like an INTERNAL/fixed disk" \
         "(removable=$removable hotplug=$hotplug transport=${tran:-none})." >&2
    echo "            This tool only wipes external/removable drives. Use" \
         "--allow-internal to override." >&2
    return 1
}

# Print identity and require the user to retype the serial (skipped with --yes).
guard_typed_confirmation() {
    local dev="$1" assume_yes="$2" serial model size answer
    model=$(lsblk -dn -o MODEL "$dev" 2>/dev/null | xargs)
    serial=$(lsblk -dn -o SERIAL "$dev" 2>/dev/null | xargs)
    size=$(lsblk -dn -o SIZE "$dev" 2>/dev/null | xargs)
    [[ -z "$serial" ]] && serial=$(basename "$(_canon "$dev")")   # loop devices have no serial
    echo "-------------------------------------------------------------" >&2
    echo " ABOUT TO DESTROY ALL DATA ON:" >&2
    echo "   Device: $dev" >&2
    echo "   Model : ${model:-<none>}" >&2
    echo "   Serial: ${serial}" >&2
    echo "   Size  : ${size}" >&2
    echo "-------------------------------------------------------------" >&2
    if [[ "$assume_yes" == "1" ]]; then
        echo " (--yes given: skipping typed confirmation)" >&2
        return 0
    fi
    read -r -p "Type the serial shown above to confirm: " answer
    if [[ "$answer" != "$serial" ]]; then
        echo "GUARD FAIL: confirmation string did not match. Aborting." >&2
        return 1
    fi
}

# Emit a device-identity JSON fragment for the report.
guard_write_identity_json() {
    local dev="$1" out="$2" model serial size_bytes
    model=$(lsblk -dn -o MODEL "$dev" 2>/dev/null | xargs)
    serial=$(lsblk -dn -o SERIAL "$dev" 2>/dev/null | xargs)
    [[ -z "$serial" ]] && serial=$(basename "$(_canon "$dev")")
    size_bytes=$(blockdev --getsize64 "$dev" 2>/dev/null || echo 0)
    cat > "$out" <<EOF
{
  "path": "$dev",
  "canonical": "$(_canon "$dev")",
  "model": "${model:-}",
  "serial": "${serial:-}",
  "size_bytes": ${size_bytes:-0}
}
EOF
}

# Run all guards in order. Returns non-zero on first failure.
run_all_guards() {
    local dev="$1" allowlist="$2" force="$3" assume_yes="$4" allow_internal="$5"
    guard_root                             || return 1
    guard_is_block_device "$dev"           || return 1
    guard_allowlist "$dev" "$allowlist"    || return 1
    guard_not_mounted "$dev"               || return 1
    guard_not_system_disk "$dev"           || return 1
    guard_external_only "$dev" "$allow_internal" || return 1
    guard_no_holders "$dev" "$force"       || return 1
    guard_typed_confirmation "$dev" "$assume_yes" || return 1
}
