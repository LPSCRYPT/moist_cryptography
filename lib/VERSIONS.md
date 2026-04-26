# Submodules

Tracked as git submodules at fixed versions. To clone the repo with
deps in one shot:

```bash
git clone --recurse-submodules <url>
# or, after a plain clone:
git submodule update --init --recursive
```

| dependency | path | source | pinned at |
|------------|------|--------|-----------|
| forge-std              | `lib/forge-std`              | https://github.com/foundry-rs/forge-std | `v1.15.0` (`0844d7e`) |
| openzeppelin-contracts | `lib/openzeppelin-contracts` | https://github.com/OpenZeppelin/openzeppelin-contracts | `v5.4.0` (`c64a1edb`) |

## Why these two only

`Poseidon2YulSponge.sol` was previously vendored under
`contracts/lib/poseidon2-evm/`. It is **our own code** — a sponge wrapper
around the BN254 permutation from
[zemse/poseidon2-evm](https://github.com/zemse/poseidon2-evm) that does not
exist in upstream. It now lives at `contracts/src/Poseidon2YulSponge.sol`,
where it belongs. We don't import anything else from poseidon2-evm.

## Updating

```bash
cd lib/forge-std
git fetch --tags
git checkout v1.16.0   # for example
cd ../..
git add lib/forge-std
git commit -m "Bump forge-std to v1.16.0"
```

Then `cd contracts && forge test` and update this file's version pin.

## Foundry resolution

`contracts/foundry.toml` points at `../lib/`:

```toml
libs = ["../lib"]
remappings = [
  "@openzeppelin/contracts/=../lib/openzeppelin-contracts/contracts/",
  "forge-std/=../lib/forge-std/src/",
]
```
