# Packaging

How `mw` and `netshell` reach a machine without a SmartScreen warning
or a Python install.

| channel | command | what it needs |
|---------|---------|---------------|
| winget | `winget install fnitguy-tech.mw` | the templates in `winget/`, rendered by the release workflow with the real hashes, attached to each release and committed under `winget/releases/<version>/`; submit a version with `wingetcreate submit winget/releases/<version>/fnitguy-tech.mw-<version>` or a pull request to microsoft/winget-pkgs |
| Scoop | `scoop bucket add fnitguy https://github.com/fnitguy-tech/netshell` then `scoop install mw` | this repository doubles as a bucket: the release workflow rewrites `bucket/*.json` on `main` from `scoop/` |
| crates.io | `cargo install mw-check` (binary `mw`), `cargo install netshell` | `cargo publish -p netshell` then `cargo publish -p mw-check` from a clean tag; `mw` was already taken on crates.io, hence `mw-check` |
| direct download | the release assets | `SHA256SUMS` sits next to them, and every binary has a build provenance attestation: `gh attestation verify <file> --owner fnitguy-tech` |

`render.sh <version> <dist>` is what the workflow runs; it works
locally against a directory holding the Windows binaries, e.g. after
`gh release download v0.2.0 -D dist`.

Code signing is the one lever not pulled here. With an Azure Trusted
Signing account or a code-signing certificate, add a signing step to
the Windows build job before the artifact upload.
