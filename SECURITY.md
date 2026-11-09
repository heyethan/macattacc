# Security policy

## Scope and intent

`macattacc` is **defensive developer tooling** for protecting software you own (see
[DISCLAIMER.md](DISCLAIMER.md)). Its runtime detectors default to **report-only**: a scan returns
detections and does nothing else unless you opt in to `.callback` or `.terminate`. Nothing here is a
wall — read the README "Honest limits" before relying on any check.

## Using it safely

- Keep `ShieldPolicy.onDetection` on `.report`. Act only on `!detection.isHighFalsePositive`.
- Do not enable `enablePtraceDenyAttach` for App-Store-bound builds (lost crash telemetry,
  notarization risk, SIGSEGV if a debugger is already attached).
- Put real enforcement on a server you control (a revocable licence), not on an in-binary
  self-check an attacker can patch out.
- This project is early, single-maintainer code with **no independent security audit**.

## Reporting a vulnerability in macattacc itself

If you find a security issue in this toolkit (a check that can be trivially bypassed in a way the
docs do not already disclose, a crash, or an unsafe default):

1. **Do not open a public issue for anything exploitable.** Use GitHub's private
   **"Report a vulnerability"** flow (Security tab → Advisories) on this repository.
2. Include the macattacc version/commit, macOS version, and a minimal reproduction.

There is no bug bounty. Expect a best-effort response from a single maintainer. Honest reports that
sharpen the README's limits are welcome as normal issues.
