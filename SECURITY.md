# Security Policy

## Supported

`pcapng_in_ada` 0.1.x receives security fixes.

## Reporting

Open a private security advisory on GitHub or contact the maintainer
(see MAINTAINERS.md). Do not open public issues for vulnerabilities.
Target first response: 72 hours.

## Parser hardening

The reader is written for untrusted input: every length is validated before
use, unknown blocks/options are skipped, and no dynamic allocation occurs.
Malformed-input drivers live in `tests/test_malformed.adb`.
