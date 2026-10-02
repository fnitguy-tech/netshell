#!/usr/bin/env bash
# Render the winget manifests and the Scoop bucket for one release.
#   packaging/render.sh <version> <dist dir with the binaries>
# Writes packaging/out/winget/<PackageIdentifier>-<version>/*.yaml for
# submission to microsoft/winget-pkgs and rewrites bucket/*.json.
set -euo pipefail

version="$1"
dist="$2"
repo="https://github.com/fnitguy-tech/netshell"
out="packaging/out/winget"

sha() { sha256sum "$dist/$1" | cut -d' ' -f1; }

render() {
  local template="$1" target="$2" sha_mw sha_netshell
  sha_mw=$(sha mw-windows-x86_64.exe)
  sha_netshell=$(sha netshell-windows-x86_64.exe)
  sed -e "s|{{VERSION}}|$version|g" \
      -e "s|{{REPO}}|$repo|g" \
      -e "s|{{SHA256_MW}}|$sha_mw|g" \
      -e "s|{{SHA256_NETSHELL}}|$sha_netshell|g" \
      "$template" > "$target"
}

for id in fnitguy-tech.mw fnitguy-tech.netshell; do
  mkdir -p "$out/$id-$version"
  for kind in "" ".installer" ".locale.en-US"; do
    render "packaging/winget/$id$kind.yaml" "$out/$id-$version/$id$kind.yaml"
  done
done

render packaging/scoop/mw.json bucket/mw.json
render packaging/scoop/netshell.json bucket/netshell.json

echo "rendered winget manifests under $out and bucket/*.json for $version"
