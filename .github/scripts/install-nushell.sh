#!/bin/sh
# Checksum-pinned nushell for the metadata-skill test. Linux runners only.
set -eu
NU_VERSION=0.116.1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset=nu-${NU_VERSION}-x86_64-unknown-linux-gnu.tar.gz
    sum=d6d8ace4be491ed8abba4026e73b60c0470b4671d7039307e7d772282ef863da
    ;;
  *)
    echo "unsupported runner: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/nu.tar.gz" \
  "https://github.com/nushell/nushell/releases/download/${NU_VERSION}/${asset}"
echo "${sum}  $tmp/nu.tar.gz" | sha256sum -c -
tar -xzf "$tmp/nu.tar.gz" -C "$tmp" "nu-${NU_VERSION}-x86_64-unknown-linux-gnu/nu"
install -m 0755 "$tmp/nu-${NU_VERSION}-x86_64-unknown-linux-gnu/nu" /usr/local/bin/nu
nu --version | grep -q "${NU_VERSION}"
