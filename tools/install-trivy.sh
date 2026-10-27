#!/usr/bin/env bash
# SHA256 закреплены по immutable GitHub release v0.76.1 (2026-10-27).
set -euo pipefail
case "$(uname -m)" in
  x86_64) asset=Linux-64bit; digest=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 ;;
  aarch64) asset=Linux-ARM64; digest=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f ;;
  *) echo 'Поддерживаются только amd64 и arm64.' >&2; exit 1 ;;
esac
destination="${1:-/usr/local/bin}"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
  "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_${asset}.tar.gz" \
  -o "$temp_dir/trivy.tar.gz"
printf '%s  %s\n' "$digest" "$temp_dir/trivy.tar.gz" | sha256sum --check --status
tar -xzf "$temp_dir/trivy.tar.gz" -C "$temp_dir" trivy
install -d -m 755 "$destination"
install -m 755 "$temp_dir/trivy" "$destination/trivy"
"$destination/trivy" --version
