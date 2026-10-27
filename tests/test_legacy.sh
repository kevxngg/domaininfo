#!/usr/bin/env bash
# Offline regressions for the classic entry point; no network commands are run.
set -eu
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./domaininfo.sh
[[ "$(validate_target 08.09.10.11)" == 08.09.10.11 ]]
[[ "$(validate_target $'example.com\r')" == example.com ]]
if validate_target 'bad domain.com'; then exit 1; fi
if validate_target 300.1.1.1; then exit 1; fi
if (parse_args -t 0 example.com) >/dev/null; then exit 1; fi
if (parse_args -t abc example.com) >/dev/null; then exit 1; fi
if (parse_args -m unknown example.com) >/dev/null; then exit 1; fi
parse_args -t 08 -m quick example.com
[[ "$THREADS" == 8 && "$MODE" == quick ]]
# Quiet must suppress module output while preserving scan execution.
run_module() { printf 'module output\n'; }
module_summary() { printf 'summary output\n'; }
save_log() { printf 'report saved\n'; }
QUIET=true; TARGET=127.0.0.1
[[ -z "$(run_scan)" ]]
# Unknown local subnet must never fall back to a guessed private network.
source ./modules/localnet.sh
LN_NETWORK=''
if localnet_discover >/dev/null; then exit 1; fi
# The modern RouterOS route must work without loading classic network tools.
portable_python=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then portable_python="$candidate"; break; fi
done
if [[ -n "$portable_python" ]]; then
    bash domaininfo.sh --mikrotik --offline --routeros-version 7.25 -q --format json |
        "$portable_python" -c 'import json,sys; d=json.load(sys.stdin)["modules"]["mikrotik"]["data"]; assert d["offline"] and d["version"] == "7.25"'
    printf '0\n' | bash domaininfo.sh |
        "$portable_python" -c 'import sys; text=sys.stdin.read(); assert "4.2.0" in text and "Kevin" in text'
fi
printf 'Classic offline regressions passed\n'
