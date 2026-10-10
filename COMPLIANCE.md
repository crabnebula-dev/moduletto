# Compliance status of moduletto

## Statement

**moduletto is free and open-source software stewarded by CrabNebula Ltd.** CrabNebula publishes it under MIT OR Apache-2.0 and supports its development on a sustained basis. CrabNebula does not sell it, place it on the market or make it available on the market as a product. It is not monetised in any form.

Under Regulation (EU) 2024/2847 (Cyber Resilience Act), CrabNebula therefore acts for moduletto as an **open-source software steward** (Article 3(14)), not as its manufacturer. The obligations for manufacturers do not apply to moduletto: CE marking, EU declaration of conformity, conformity assessment, Annex I essential requirements, Annex II user information and Annex VII technical documentation. The lighter steward regime of Article 24 applies instead, and is set out below.

## Basis in the Regulation

Article 2(1) applies the CRA to products with digital elements **made available on the market**. Article 3(22) defines making available on the market as supply for distribution or use on the Union market **in the course of a commercial activity, whether in return for payment or free of charge**.

The operative basis for this status is therefore not that moduletto is free of charge. Free supply in the course of a commercial activity is still making available on the market. The basis is that CrabNebula supplies moduletto **outside any commercial activity**: it is published as free and open-source software (Article 3(48)), with no price, no paid support tied to it, and no other monetisation. Recitals 18 and 19 describe this distinction.

An open-source software steward is a legal person, other than a manufacturer, that systematically provides sustained support for the development of specific free and open-source software intended for commercial activities, and ensures its viability (Article 3(14)). That describes CrabNebula's role here: moduletto is intended to be used by others, including in commercial products, and CrabNebula maintains it.

## Obligations CrabNebula accepts as steward

Article 24 sets three obligations. CrabNebula meets them as follows.

| Article | Obligation | How it is met |
|---|---|---|
| 24(1) | Put in place and document a cybersecurity policy that fosters secure development and effective vulnerability handling, including voluntary reporting of vulnerabilities | The policy in the next section |
| 24(2) | Cooperate with market surveillance authorities, on request, to mitigate risks posed by the software | CrabNebula answers such requests through the contact below and provides the documentation it holds |
| 24(3) | Article 14(1) reporting, to the extent CrabNebula is involved in development; Article 14(3) and (8), to the extent severe incidents affect systems CrabNebula provides for development | CrabNebula notifies actively exploited vulnerabilities in moduletto and qualifying incidents through the single reporting platform, within the Article 14 deadlines |

Article 64(10)(b) excludes administrative fines against open-source software stewards. That exclusion does not reduce the obligations above.

## Cybersecurity policy (Article 24(1))

**Scope.** This policy covers the moduletto source code in this repository, its build and test configuration, and its published releases.

**Secure development.**

- Changes are merged by the maintainer. Merge commits and releases are signed; commits that arrive through pull requests may carry the contributor's signature or none.
- Security reviews and their remediation are recorded in `audits/`, each with the reviewed commit hash and a timestamp. Findings are fixed in the tree before the review is published.
- The ML-KEM implementation (`src/kem.rs`) is tested against the NIST ACVP vectors for ML-KEM-512 and ML-KEM-768. The tests cover key generation, encapsulation, decapsulation and the FIPS 203 input checks (`tests/kem_kat.rs`). CI runs them on every push and pull request (`.github/workflows/ci.yml`), on x86-64 Linux and on arm64 macOS, so both the scalar and the NEON code paths are tested.
- Secret-dependent arithmetic uses the branch-free code paths documented in the crate. The Coq proofs in `proofs/` cover the Barrett reduction, the modular arithmetic, the constant-time layer and the NTT. The fuzz targets in `fuzz/` check the NTT and the constant-time arithmetic against reference results.
- Secret material (seeds, noise, Keccak states, re-encryption state, internal key structs) is wiped with `zeroize`, and a stack scrub follows each ML-KEM operation. Decapsulation does not branch on secret data; the implicit-rejection comparison goes through `subtle` and the rounding divisions by q are fixed-point multiplications. On AArch64 the ML-KEM entry points run with `PSTATE.DIT` set.
- Timing behaviour is checked in CI by a dudect statistical test and a Valgrind-based (ctgrind-style) secret-tracking check; the Rocq proofs are built in CI as well.
- Dependencies are kept minimal: `subtle` and `zeroize`, plus `getrandom` behind an optional feature. CI runs `cargo audit` against the RustSec advisory database on every push, and Dependabot proposes dependency and GitHub Action updates weekly. Known-vulnerable dependencies are removed or updated when advisories are published.

**Vulnerability handling.**

- Report a vulnerability privately through GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), or through the channel in CrabNebula's `security.txt` (<https://crabnebula.dev/.well-known/security.txt>: `security@crabnebula.dev`, PGP key, disclosure policy). Please do not open a public issue. `SECURITY.md` in the repository repeats this.
- CrabNebula acknowledges reports within 5 working days and agrees a disclosure date with the reporter. The default is 90 days after the report, or earlier once a fix is released.
- Fixes are released as a new version with a security advisory that names the affected versions. The advisory credits the reporter unless they ask otherwise.
- CrabNebula notifies actively exploited vulnerabilities under Article 14(1), as described above.

**Voluntary reporting.** CrabNebula shares vulnerability information with users and downstream maintainers through GitHub security advisories. It encourages them to report vulnerabilities they find in moduletto through the same channel.

## Information for integrators

A manufacturer that integrates moduletto into a product it places on the market must exercise due diligence on it as a component (Article 13(5)). That manufacturer, not CrabNebula, carries the CRA obligations for its product. The following supports that due diligence.

| | |
|---|---|
| Licence | MIT OR Apache-2.0. Releases before the relicensing were published under the PolyForm Noncommercial License 1.0.0. |
| Algorithms | ML-KEM-512 and ML-KEM-768 per FIPS 203, in `moduletto::kem` |
| Test evidence | NIST ACVP vectors in `tests/kat/`, regenerated by `tests/kat/extract.mjs` from a named ACVP-Server commit |
| Validation | Not validated under FIPS 140-3 (CMVP) or any other certification scheme |
| Randomness | None built in by default. Callers supply randomness from a CSPRNG to the `*_derand` functions. The optional `getrandom` feature adds `keygen()` and `encaps(ek)` backed by the OS CSPRNG. |
| Secret handling | Wiped with `zeroize` inside the crate; returned keys and shared secrets are plain arrays the caller must wipe |
| Security reviews | `audits/`, with reviewed commit and timestamp |
| Dependencies | `subtle` (BSD-3-Clause), `zeroize` (Apache-2.0 OR MIT), optional `getrandom` (MIT OR Apache-2.0) |
| Third-party material | XKCP Keccak (public domain); pqcrystals Kyber reference constants (CC0-1.0 or Apache-2.0); NIST ACVP vectors (US Government work). Full attributions, dependency licences and licensing history in `NOTICE`. |
| Vulnerability reports | GitHub private vulnerability reporting on this repository |

## What would change this

This status holds only while CrabNebula supplies moduletto outside any commercial activity. Re-run the assessment before any of the following.

| Change | Effect |
|---|---|
| Charging for moduletto, or for a build, a licence exception or a distribution of it | Making available on the market. CrabNebula would become its manufacturer and the full CRA regime would apply. |
| Offering paid technical support for moduletto beyond recovering actual costs, or making it a condition of a paid service | Likely a commercial activity (Recitals 18 and 19). Assess before offering. |
| Monetising moduletto in another way, for example by processing personal data for purposes other than its security, compatibility or interoperability | Likely a commercial activity. Assess before doing so. |
| Embedding moduletto in a CrabNebula product that is placed on the market | moduletto stays stewarded open-source software. The CrabNebula product is in scope, and CrabNebula as its manufacturer must exercise Article 13(5) due diligence on moduletto as a component. |
| Transferring stewardship, or ending sustained support | Update this document. Article 24 applies to whoever acts as steward. |

Treat a change of distribution or funding model as a compliance event.

## Other instruments

This statement covers the CRA only. It is not an assessment against export control rules for cryptography, the GDPR, the NIS2 Directive or any other instrument. It says nothing about products that use moduletto.

## Record

| | |
|---|---|
| Subject | moduletto: modular arithmetic, NTT and ML-KEM (FIPS 203) for lattice cryptography |
| Status | Free and open-source software, stewarded by CrabNebula Ltd. Not placed or made available on the market as a product. Steward obligations under Article 24 apply. |
| Steward | CrabNebula Ltd, Malta (C 103590) |
| Assessed | 2026-09-27 |
| Owner | Denjell |
| Re-assess | On any change in the table above, or on a change to CRA scope guidance |
