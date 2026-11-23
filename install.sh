#!/usr/bin/env bash
# Portable installer; optional Bash dependencies: bash install.sh --legacy
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
legacy=false
case "${1:-}" in
    --legacy) legacy=true ;;
    --help|-h) printf '%s\n' 'Usage: bash install.sh [--legacy]'; exit 0 ;;
    '') ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
esac
admin() {
    if [[ "$(id -u)" == 0 ]]; then "$@"
    elif command -v sudo >/dev/null 2>&1; then sudo "$@"
    else echo 'Install Python 3.10+ with your package manager.' >&2; exit 1
    fi
}
find_python() {
    local candidate
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(sys.version_info < (3,10))' 2>/dev/null; then
            PYTHON="$candidate"; return 0
        fi
    done
    return 1
}
if ! find_python; then
    if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *com.termux* ]]; then
        pkg update
        pkg install -y python
    elif [[ "$(uname -s)" == Darwin ]] && command -v brew >/dev/null 2>&1; then
        brew install python
    elif command -v apt-get >/dev/null 2>&1; then
        admin apt-get update
        admin apt-get install -y python3
    elif command -v dnf >/dev/null 2>&1; then
        admin dnf install -y python3
    elif command -v pacman >/dev/null 2>&1; then
        admin pacman -Syu --needed python
    else
        echo 'Install Python 3.10+ and run the installer again.' >&2; exit 1
    fi
    find_python || { echo 'Python 3.10+ is required.' >&2; exit 1; }
fi
if "$legacy"; then
    if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *com.termux* ]]; then
        pkg update
        pkg install -y bash curl dnsutils whois nmap openssl-tool coreutils netcat-openbsd traceroute
    elif [[ "$(uname -s)" == Darwin ]]; then
        command -v brew >/dev/null 2>&1 || { echo 'Install Homebrew for the Bash modules.' >&2; exit 1; }
        brew install bash bind whois nmap openssl coreutils
    elif command -v apt-get >/dev/null 2>&1; then
        admin apt-get update
        admin apt-get install -y bash curl dnsutils whois nmap openssl coreutils traceroute netcat-openbsd
    elif command -v dnf >/dev/null 2>&1; then
        admin dnf install -y bash curl bind-utils whois nmap openssl coreutils traceroute nmap-ncat
    elif command -v pacman >/dev/null 2>&1; then
        admin pacman -Syu --needed bash curl bind whois nmap openssl coreutils traceroute gnu-netcat
    else
        echo 'Install the Bash tools listed in README.md manually.' >&2; exit 1
    fi
fi
bin_dir="${HOME}/.local/bin"
if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *com.termux* ]]; then
    bin_dir="${PREFIX:?PREFIX is not set}/bin"
fi
mkdir -p "$bin_dir"
printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$(command -v "$PYTHON")" "$SCRIPT_DIR/domaininfo.py" > "$bin_dir/domaininfo"
chmod +x "$bin_dir/domaininfo"
"$PYTHON" "$SCRIPT_DIR/domaininfo.py" --doctor
# Bash completion in the standard per-user folder; bash-completion loads it on its own.
completion_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *com.termux* ]]; then
    completion_dir="$PREFIX/share/bash-completion/completions"
fi
mkdir -p "$completion_dir"
"$PYTHON" "$SCRIPT_DIR/domaininfo.py" --completion bash > "$completion_dir/domaininfo"
printf '\nInstalled: %s/domaininfo\n' "$bin_dir"
printf 'If it is not in PATH: export PATH="%s:$PATH"\n' "$bin_dir"
printf 'Bash completion (TAB): %s/domaininfo\n' "$completion_dir"
printf 'Zsh: add this line to ~/.zshrc  eval "$(domaininfo --completion zsh)"\n'
