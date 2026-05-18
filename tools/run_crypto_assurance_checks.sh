#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"

python3 tools/check_toolchain.py
python3 -m compileall -q tools
python3 tools/check_zk_surface_manifest.py
python3 tools/check_byte_binding_tests.py
python3 tools/check_metadata_authority.py
python3 tools/check_verifier_manifest.py
python3 tools/generate_poseidon2_vectors.py --check
(
  cd contracts
  forge build
  forge test --match-contract 'Poseidon2|GeneratedVerifierMatrix|FeatureNFT|TransferFeature|TransferShadow|SolveShadow|MintShadow|MutateSlot|MutateBatch|InsertFeature' -vv
)
