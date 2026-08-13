# Changelog

`docs/plan/06-delivery.md` states that an MSRV increase is a minor version bump and appears here.
The `fidelity` crate follows SemVer. Every other crate in the workspace is an internal
implementation detail and carries no compatibility promise, so a change to one of them appears here
only when it changes what `fidelity` exposes.

This file records released versions. The work before the first release lives in the git history and
in `evidence/README.md`, which states what each platform proved and what it did not.

## Unreleased

No release exists yet. No platform is supported, because a supported label needs the full release
evidence that `docs/plan/05-verification.md` defines.
