#!/usr/bin/env bash
# Run Reko's headless CLI on a binary and consolidate its emitted C into a
# single output file. Invoked by docker/reko.Dockerfile's ENTRYPOINT.
#
# Usage: decompile.sh <input-binary> <output-c-path> [native-provenance-path]
#
# Reko writes its output next to a working directory; it emits one or more
# *.c files (typically "<stem>_text.c" plus globals/types). We run Reko, then
# concatenate every generated .c into the requested output path so decbench can
# read whole-program C from one file.
set -euo pipefail

IN="${1:?input binary required}"
OUT="${2:?output .c path required}"
PROVENANCE="${3:-}"

if [ -n "$PROVENANCE" ]; then
    export DECBENCH_REKO_PROVENANCE="$PROVENANCE"
fi

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
    echo "reko-decompile.sh: could not find Reko CLI under /opt/reko" >&2
    exit 2
fi

# Current Reko releases use the decompile subcommand. Fall back to the legacy
# direct invocation so older pinned images remain usable.
"${REKO_CMD[@]}" decompile "$STEM" >/dev/null 2>&1 || \
    "${REKO_CMD[@]}" "$STEM" >/dev/null 2>&1 || true

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
done < <(find "$WORK" -name '*.c' -print0 2>/dev/null)

if [ "$found" -eq 0 ]; then
    echo "reko-decompile.sh: Reko produced no .c output for $STEM" >&2
    exit 3
fi
