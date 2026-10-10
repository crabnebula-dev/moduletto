# Security policy

moduletto is free and open-source software stewarded by CrabNebula Ltd. The
full cybersecurity policy, written for Article 24 of the EU Cyber Resilience
Act, is in [COMPLIANCE.md](COMPLIANCE.md). Completed security reviews and
their remediation are recorded in [audits/](audits/).

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting on this
repository (Security tab, "Report a vulnerability"). Please do not open a
public issue.

- Acknowledgement within 5 working days.
- Disclosure date agreed with the reporter; default 90 days after the report,
  or earlier once a fix is released.
- Fixes ship as a new version with a GitHub security advisory naming the
  affected versions. Reporters are credited unless they ask otherwise.

## Scope

The source in this repository, its build and test configuration, and its
published releases. The library has no RNG of its own unless the `getrandom`
feature is enabled; see the `kem` module documentation for what callers must
supply and wipe.
