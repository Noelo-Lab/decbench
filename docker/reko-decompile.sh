#!/usr/bin/env bash
# Run Reko's headless CLI on a binary and consolidate its emitted C into a
# single output file. Invoked by docker/reko.Dockerfile's ENTRYPOINT.
#
# Usage: decompile.sh <input-binary> <output-c-path> [native-provenance-path] [auto|thumb]
#
# Reko writes its output next to a working directory; it emits one or more
# *.c files (typically "<stem>_text.c" plus globals/types). We run Reko, then
# concatenate every generated .c into the requested output path so decbench can
# read whole-program C from one file.
set -euo pipefail

IN="${1:?input binary required}"
OUT="${2:?output .c path required}"
PROVENANCE="${3:-}"
MODE="${4:-auto}"

case "$MODE" in
    auto) ;;
    thumb) export DECBENCH_REKO_FORCE_THUMB=1 ;;
    *)
        echo "reko-decompile.sh: mode must be 'auto' or 'thumb', got '$MODE'" >&2
        exit 2
        ;;
esac

if [ -n "$PROVENANCE" ]; then
    export DECBENCH_REKO_PROVENANCE="$PROVENANCE"
fi

OUT_DIR="$(dirname "$OUT")"
STATUS_PATH="$OUT_DIR/reko-status.json"
LOG_PATH="$OUT_DIR/reko.log"
PRIMARY_RC=-1
LEGACY_RC_JSON=null
USED_LEGACY=false
CLI_FOUND=false
CLI_SUCCEEDED=false
C_FILE_COUNT=0
WRAPPER_RC=0

write_status() {
    printf '%s\n' \
        "{\"schema\":\"decbench-reko-status-v1\",\"mode\":\"$MODE\",\"cli_found\":$CLI_FOUND,\"primary_returncode\":$PRIMARY_RC,\"legacy_returncode\":$LEGACY_RC_JSON,\"used_legacy\":$USED_LEGACY,\"cli_succeeded\":$CLI_SUCCEEDED,\"c_file_count\":$C_FILE_COUNT,\"wrapper_returncode\":$WRAPPER_RC}" \
        > "$STATUS_PATH"
}

WORK="$(mktemp -d)"
cp "$IN" "$WORK/"
STEM="$(basename "$IN")"
cd "$WORK"

# Locate the Reko command-line driver across upstream layouts.
REKO_CMD=()
if [ -x /opt/reko/decompile ]; then
    REKO_CMD=(/opt/reko/decompile)
elif [ -x /opt/reko/reko ]; then
    REKO_CMD=(/opt/reko/reko)
elif [ -f /opt/reko/decompile.dll ]; then
    REKO_CMD=(dotnet /opt/reko/decompile.dll)
elif [ -f /opt/reko/reko.dll ]; then
    REKO_CMD=(dotnet /opt/reko/reko.dll)
elif [ -f /opt/reko/CmdLine.dll ]; then
    REKO_CMD=(dotnet /opt/reko/CmdLine.dll)
else
    # Last resort: any *.dll that looks like the driver.
    DLL="$(ls /opt/reko/*CmdLine*.dll /opt/reko/reko*.dll 2>/dev/null | head -1 || true)"
    if [ -n "$DLL" ]; then
        REKO_CMD=(dotnet "$DLL")
    fi
fi

if [ "${#REKO_CMD[@]}" -eq 0 ]; then
    echo "reko-decompile.sh: could not find Reko CLI under /opt/reko" | tee "$LOG_PATH" >&2
    WRAPPER_RC=2
    write_status
    exit 2
fi
CLI_FOUND=true

# Current Reko releases use the decompile subcommand. Fall back to the legacy
# direct invocation so older pinned images remain usable.
CLI_LOG="$WORK/reko-cli.log"
set +e
"${REKO_CMD[@]}" decompile "$STEM" >"$CLI_LOG" 2>&1
PRIMARY_RC=$?
if [ "$PRIMARY_RC" -eq 0 ]; then
    CLI_SUCCEEDED=true
else
    USED_LEGACY=true
    "${REKO_CMD[@]}" "$STEM" >>"$CLI_LOG" 2>&1
    LEGACY_RC=$?
    LEGACY_RC_JSON=$LEGACY_RC
    if [ "$LEGACY_RC" -eq 0 ]; then
        CLI_SUCCEEDED=true
    fi
fi
set -e
cp "$CLI_LOG" "$LOG_PATH"

# Reko writes outputs under <stem>/ or alongside the input. Gather every .c.
: > "$OUT"
found=0
while IFS= read -r -d '' f; do
    {
        echo "// ==== $(basename "$f") ===="
        cat "$f"
        echo
    } >> "$OUT"
    found=1
    C_FILE_COUNT=$((C_FILE_COUNT + 1))
done < <(find "$WORK" -name '*.c' -print0 2>/dev/null)

if [ "$found" -eq 0 ]; then
    echo "reko-decompile.sh: Reko produced no .c output for $STEM" >&2
    WRAPPER_RC=3
elif [ "$CLI_SUCCEEDED" != true ]; then
    echo "reko-decompile.sh: both Reko CLI invocations failed for $STEM" >&2
    tail -n 20 "$LOG_PATH" >&2 || true
    WRAPPER_RC=4
fi

write_status
exit "$WRAPPER_RC"
