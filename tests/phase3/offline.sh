#!/bin/bash
# Local-only Phase 3 regressions. No SSH, provider API, QEMU, nft mutation, or deployment.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1

cargo build --workspace --locked
cargo test --workspace --locked
python3 -B -m unittest discover -s tests/phase2 -p 'test_*.py' -v
python3 -B -m unittest discover -s tests/phase3 -p 'test_*.py' -v

while IFS= read -r script; do
  bash -n "$script"
done < <(rg --files infra/hetzner tests/phase2 tests/phase3 -g '*.sh')

# The live acceptance skeleton must distinguish unavailable trusted observations from success.
set +e
bash tests/phase3/acceptance.sh
status=$?
set -e
[ "$status" = 77 ] || { echo "live skeleton returned unexpected status $status" >&2; exit 1; }
echo 'Phase 3 offline: PASS. Live G1-G5: BLOCKED (separate operator deployment and observations required).'
