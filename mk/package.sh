# This only works on Windows, using MinGW.
set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty.
# https://stackoverflow.com/a/5737794
if [[ -n "$(git status --porcelain)" ]]; then
  echo Repository is dirty.
  exit 1
fi

cargo clean --target-dir=target/pregenerate_asm
RING_PREGENERATE_ASM=1 CC_AARCH64_PC_WINDOWS_MSVC=clang \
  cargo build -p ring --target-dir=target/pregenerate_asm
cargo package -p ring --allow-dirty
