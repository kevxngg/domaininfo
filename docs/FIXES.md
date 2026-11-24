# Version 4 fixes

Version 4.2 adds a guided menu with back navigation, validation that lets you retry, per-module progress and a report viewer. The Bash entry point without arguments opens this menu; the previous menu is still available with `--legacy`. Commands with a target keep their JSON output.

Version 4.1 adds the portable, version-based RouterOS audit, with a dated catalog and evidence kept separate from the applicability of a CVE. See [MIKROTIK.md](MIKROTIK.md).

No logs from the old Termux session were found. These fixes come from code review and reproducible tests; they do not prove what the exact error in that session was.

| Problem found | Fix |
|---|---|
| The installer hid stderr and package failures behind grep/head pipelines | Installation with `set -euo pipefail`, visible output and immediate failure |
| One failed optional package blocked installing the base set | Python is the only base requirement; classic tools with `--legacy` |
| Unquoted alias around paths with spaces, symlink that altered SCRIPT_DIR | Launcher that keeps the quoted absolute path, without modifying bashrc/zshrc |
| Bash associative arrays used on macOS with Bash 3.2 | Native Python core and a Bash 4+ check in the classic entry point |
| GNU `timeout` does not exist under that name on macOS | `gtimeout` is recognized in the classic entry point; Python does not need it |
| `date -Iseconds` and `date -d` are not portable | Timestamp with an explicit format and a BSD fallback for the HTTP certificate date |
| whois/host dependencies were mandatory for every mode | Only the common curl/dig; WHOIS is skipped with a message if missing; independent Python core |
| RAW permissions for Nmap on Termux | Classic TCP scan with `-sT`; the portable core uses TCP connections without root |
| RETURN traps could persist and delete other functions' temporary files | Explicit cleanup of temporary files and registration for interrupts in the classic entry point |
| Zero or invalid concurrency and unknown modes were accepted | Argument validation in both entry points |
| IPv4 with 08/09 octets triggered Bash octal arithmetic | Explicit base-ten conversion |
| Quiet still printed modules and the menu looped on EOF | Silent scan output and menu exit when stdin closes |
| LAN assumed `192.168.1.0/24` when the network could not be detected | Do not start discovery on a guessed network |
| Python traceroute labeled TCP as hops without measuring TTL | Remove that fallback and state the permission limitation |
| OpenSSL could read `Cipher: 0000` as negotiated TLS | Reject NONE/0000 ciphers, send SNI and do not mistake a local failure for a disabled protocol |
| A report called complete truncated the log to 200 lines | The classic HTML includes every line of the file |

## Validation

The portable suite covers IPv4/IPv6/IDNA input, invalid arguments, BOM/CRLF batch files, local open/closed ports, HTTP headers, HTTP 404 responses, maximum response size, TLS/RDAP errors, traceroute errors, HTML escaping, unique names, quiet mode and write failures. TLS and RDAP are tested with mocks; they are not a validation against every real provider.

The declared compatibility of the core is Python 3.10+ and standard APIs. Network functions depend on the machine's connectivity and permissions. The GitHub suite includes Windows/Linux/macOS; it does not simulate Android restrictions. The legacy modules need an additional review to confirm findings and are not a verified CVE scanner.
