#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
  echo "No Cargo workspace found; preflight skipped."
  exit 0
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

if [[ "${1:-}" != "--skip-tests" ]]; then
  cargo test --workspace
fi
