#!/usr/bin/env bash
# Verify that prebuilt addon binaries export all required FFI symbols.
#
# Run after `make addon-all` or `make addon-install` to catch stale binaries
# that are missing new symbols. Exits non-zero if any addon is missing symbols.

set -euo pipefail

# Required symbols — keep in sync with intercept/src/nodejs/stack.rs resolve_stack_parser_ffi()
REQUIRED_SYMBOLS=(
    malwi_parse_frame_parameters
    malwi_parse_frame_parameters_with_isolate
    malwi_free_frame_result
    malwi_walk_to_js_frame
    malwi_get_js_frame_from_isolate
    malwi_get_platform_info
    malwi_get_type_name
    malwi_get_current_function_name
    malwi_capture_stack_trace
    malwi_get_caller_source_location
    malwi_get_top_source_location
    malwi_free_source_location
    malwi_classify_tagged_value
    malwi_free_parameter_info
)

errors=0

for addon in node-addon/prebuilt/*/node*/v8_introspect.node; do
    [ -f "$addon" ] || continue

    # Get exported symbols (nm -D for ELF, nm -gU for Mach-O)
    if file "$addon" | grep -q 'Mach-O'; then
        exported=$(nm -gU "$addon" 2>/dev/null | awk '{print $NF}' | sed 's/^_//')
    else
        exported=$(nm -D "$addon" 2>/dev/null | awk '{print $NF}')
    fi

    missing=()
    for sym in "${REQUIRED_SYMBOLS[@]}"; do
        if ! echo "$exported" | grep -q "^${sym}$"; then
            missing+=("$sym")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo "FAIL: $addon missing symbols: ${missing[*]}"
        errors=$((errors + 1))
    else
        echo "  ok: $addon (${#REQUIRED_SYMBOLS[@]} symbols)"
    fi
done

if [ $errors -gt 0 ]; then
    echo ""
    echo "ERROR: $errors addon(s) have missing symbols. Rebuild with: make addon-all"
    exit 1
fi

echo "All prebuilt addons export required symbols."
