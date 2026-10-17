#!/bin/sh
# Start Tor in the background (if not already running), then exec darkwatch.
set -e

if command -v tor >/dev/null 2>&1 && [ -z "${DW_DISABLE_TOR:-}" ]; then
    tor &
fi

exec darkwatch "$@"
