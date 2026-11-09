# Disclaimer: defensive use only

`macattacc` is a tool for **developers protecting software they own.** It is meant to raise the
cost of cracking a licence, tampering with a running app, or lifting your code — on *your* binary.

## Permitted

- Hardening and self-protecting applications you author or are authorized to protect.
- Detecting tampering, debugging, and instrumentation of your own process at runtime.
- Packaging build-hardening settings for your own release pipeline.

## Not permitted / out of scope

- Evading antivirus, EDR, MDM, or any security product.
- Hiding malware, or protecting software you do not own or have no right to protect.
- Attacking, bypassing, or interfering with anyone else's software or systems.

## The honest dual-use line

Be straight about this: the **detection** half of this toolkit (debugger checks, anti-attach,
instrumentation detection) is the same category of code that sandbox-evading malware uses. A
DISCLAIMER cannot make that line cleaner than it is. The genuine differentiator here is the
**protective build-hardening** half — strip/metadata presets and (phase 2) obfuscation — which only
makes sense for someone shipping their own product.

Use it on your own software. The authors accept no liability for misuse (see `LICENSE`).
