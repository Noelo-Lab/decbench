#!/usr/bin/env bash
# Run Reko's headless CLI on a binary and consolidate its emitted C into a
# single output file. Invoked by docker/reko.Dockerfile's ENTRYPOINT.
#
# Usage: decompile.sh <input-binary> <output-c-path>
#
# Reko writes its output next to a working directory; it emits one or more
# *.c files (typically "<stem>_text.c" plus globals/types). We run Reko, then
# concatenate every generated .c into the requested output path so decbench can
# read whole-program C from one file.
set -euo pipefail

IN="${1:?input binary required}"
OUT="${2:?output .c path required}"

WORK="$(mktemp -d)"
cp "$IN" "$WORK/"
STEM="$(basename "$IN")"
cd "$WORK"

# Locate the Reko command-line driver. Recent publishes produce an executable
# named "decompile"; older/self-contained layouts ship a CmdLine.dll.
REKO_EXE=""
if [ -x /opt/reko/decompile ]; then
    REKO_EXE="/opt/reko/decompile"
elif [ -f /opt/reko/decompile.dll ]; then
    REKO_EXE="dotnet /opt/reko/decompile.dll"
elif [ -f /opt/reko/CmdLine.dll ]; then
    REKO_EXE="dotnet /opt/reko/CmdLine.dll"
else
    # Last resort: any *.dll that looks like the driver.
    DLL="$(ls /opt/reko/*CmdLine*.dll /opt/reko/reko*.dll 2>/dev/null | head -1 || true)"
    if [ -n "$DLL" ]; then
        REKO_EXE="dotnet $DLL"
    fi
fi

if [ -z "$REKO_EXE" ]; then
    echo "reko-decompile.sh: could not find Reko CLI under /opt/reko" >&2
    exit 2
fi

# Run Reko headless. Reko auto-detects most formats; --c hints C output.
# (Different Reko versions accept slightly different flags; run permissively.)
$REKO_EXE "$STEM" >/dev/null 2>&1 || \
    $REKO_EXE --c "$STEM" >/dev/null 2>&1 || true

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
