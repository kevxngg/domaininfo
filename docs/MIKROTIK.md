# RouterOS audit

Author: Kevin (@kevxngg). Catalog review: **2026-10-26**.

To use the version 4.2 wizard, run `python3 domaininfo.py`, choose **5 · MikroTik / RouterOS**, and select either a device review or an offline review. The wizard lets you go back, adjust ports and read a summary of the advisories before opening the full report.

## Sources and scope

The ranges in the [CERT Polska advisory](https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/) were cross-checked against the [MikroTik publication updated in October](https://mikrotik.com/supportsec/september-2026-vulnerability/). The catalog contains these six advisories:

| Advisory | Component |
|---|---|
| CVE-2026-67276 | SSH authentication |
| CVE-2026-67277 | Bandwidth-test |
| CVE-2026-67278 | Certificates and host keys |
| CVE-2026-67279 | SSH channels |
| CVE-2026-67281 | WebFig |
| CVE-2026-86060 | SSH users |

The exact ranges are kept per advisory in `routeros.py` and included in every report. The intervals from the researcher who published the advisory are used; an impact is never extended to a whole branch based on a general summary. For example, according to CERT Polska the WebFig advisory starts at 7.20 and the SSH key validation advisory at 7.9.

The complete certificate fix is in **7.24.3** and **7.23.6**: **7.24.2**, **7.23.4** and **7.23.5** keep a potential advisory in this catalog. RouterOS 6 is outside that specific advisory. The other limits are evaluated separately.

The snapshot of reference versions comes from the [official changelog](https://mikrotik.com/download/changelogs): stable 7.25, long-term 7.23.8 and the 6 branch at 6.49.23. A version older than stable does not mean you must automatically move away from long-term. Check your device's architecture, channel, compatibility and update policy. This catalog does not update itself and does not cover every historical or future CVE.

## How the evidence is gathered

- Without `--offline`, TCP connections are attempted to a limited list of management services. `--ports` replaces that list.
- The initial SSH banner is read without sending credentials, along with the public HTTP/HTTPS landing page. No redirect is followed. HTTPS keeps certificate verification.
- An SSH protocol number or another server's version is not interpreted as RouterOS: a RouterOS marker close to the version is required.
- `--routeros-version` lets you use a version from your inventory; it is recorded as `user_supplied`. A banner version is recorded as `public_banner` and is not an authenticated identity.
- Contradictory versions force a manual review. Unknown versions, beta/rc builds or branches other than 6/7 never produce a "patch applied" conclusion.
- `--web-port` and `--scheme` set a custom web port; `--ssh-port` sets the SSH banner port. Include those ports in `--ports` if you provide your own list.

`--offline` mode requires a version, does not accept targets or batch input, and does not resolve DNS, scan ports or query external services.

## Reading the report

| Advisory status | Meaning |
|---|---|
| `potentially_affected` | The given version is inside an affected interval in the catalog |
| `not_in_affected_range` | The version is outside that advisory's intervals |
| `unknown_version` | A version to compare against is missing |
| `manual_review` | Unevaluated branch/beta/rc or contradictory evidence |

`confirmed` stays `false`: no attempt is made to exploit the flaw. Port exposure is reported separately; a closed or moved port does not remove the applicability of a version-based advisory. The checks do not validate firewall, VLANs, user permissions, Flagged state or internal configuration; those reviews appear as recommendations for the administrator.

## Examples

```bash
python3 domaininfo.py -m mikrotik --offline --routeros-version 7.24.2
python3 domaininfo.py -m mikrotik --offline --routeros-version 7.25
python3 domaininfo.py -m mikrotik --routeros-version 7.23.8 192.168.88.1
bash domaininfo.sh --mikrotik --offline --routeros-version 7.25
```

On Windows use `python` or `py -3`. On Termux it works with Python without root. The automated validation uses a simulated local server and covers patch boundaries, contradictory versions, a missing version, custom ports and the absence of connections in offline mode; it does not replace a test on real MikroTik hardware.
