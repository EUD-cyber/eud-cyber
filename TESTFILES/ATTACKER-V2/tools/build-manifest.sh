#!/usr/bin/env bash

set -euo pipefail

#
# MrNobody - Update Manifest Builder
#
# Generates:
#   TESTFILES/ATTACKER-V2/update-manifest.txt
#
# Run this script whenever files are added or changed
# before committing/pushing to GitHub.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFEST="${BASE_DIR}/update-manifest.txt"
TMP_MANIFEST="$(mktemp)"

cleanup() {
    rm -f "$TMP_MANIFEST"
}

trap cleanup EXIT

echo "========================================"
echo " MrNobody - Build Update Manifest"
echo "========================================"
echo
echo "Source:   $BASE_DIR"
echo "Manifest: $MANIFEST"
echo

#
# Manifest header
#
{
    echo "# MrNobody Update Manifest"
    echo "# Generated automatically - DO NOT EDIT"
    echo "# Format: SHA256|PATH"
    echo
} > "$TMP_MANIFEST"

FILE_COUNT=0

#
# Find every file belonging to MrNobody.
#
while IFS= read -r -d '' FILE; do

    RELATIVE="${FILE#${BASE_DIR}/}"

    #
    # Files/directories that must NOT be distributed
    # to installed IncidentVMs.
    #
    case "$RELATIVE" in

        update-manifest.txt)
            continue
            ;;

        tools/*)
            continue
            ;;

        state/*)
            continue
            ;;

        logs/*)
            continue
            ;;

        runtime/*)
            continue
            ;;

        reports/*)
            continue
            ;;

        config/local.conf)
            continue
            ;;

        *.pyc)
            continue
            ;;

        */__pycache__/*)
            continue
            ;;

        .git/*)
            continue
            ;;

    esac

    #
    # Calculate SHA256
    #
    SHA256="$(sha256sum "$FILE" | awk '{print $1}')"

    printf '%s|%s\n' \
        "$SHA256" \
        "$RELATIVE" \
        >> "$TMP_MANIFEST"

    ((FILE_COUNT+=1))

done < <(
    find "$BASE_DIR" \
        -type f \
        -print0 \
        | sort -z
)

#
# Replace old manifest atomically.
#
mv "$TMP_MANIFEST" "$MANIFEST"

trap - EXIT

echo
echo "Manifest generated successfully."
echo
echo "Files included: $FILE_COUNT"
echo
echo "----------------------------------------"
cat "$MANIFEST"
echo "----------------------------------------"