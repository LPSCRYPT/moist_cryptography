#!/usr/bin/env python3
"""Start a full localhost ShadowNFT dashboard run.

This is a developer-only harness. It starts Anvil, deploys the current contracts,
optionally mints the committed atomic mint fixture with real proofs, writes a
browser-only dashboard/local.json config, and serves dashboard/ on localhost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

REPO = Path(__file__).resolve().parents[1]
CONTRACTS = REPO / "contracts"
DASHBOARD = REPO / "dashboard"
STATE_DIR = REPO / ".local"
STATE_FILE = STATE_DIR / "local_dashboard_state.json"
DASHBOARD_CONFIG = DASHBOARD / "local.json"
ANVIL_LOG = STATE_DIR / "anvil.log"
DASHBOARD_LOG = STATE_DIR / "dashboard.log"
RPC_URL = "http://127.0.0.1:8545"
DASHBOARD_PORT = 8080
CHAIN_ID = 31337

ANVIL_PROFILES = [
    {
        "label": "Anvil 0 / fixture owner",
        "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "evmPk": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    },
    {
        "label": "Anvil 1",
        "address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
        "evmPk": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    },
    {
        "label": "Anvil 2",
        "address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        "evmPk": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    },
]

GRUMPKIN_ORDER = 21888242871839275222246405745257275088696311157297823662689037894645226208583
FIXTURE = CONTRACTS / "test" / "fixtures" / "atomic_mint" / "atomic_mint_demo"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stop", action="store_true", help="Stop the remembered local Anvil/dashboard processes")
    ap.add_argument("--status", action="store_true", help="Print remembered process status")
    ap.add_argument("--skip-mint", action="store_true", help="Deploy only; do not run the real proof mint fixture")
    ap.add_argument("--no-serve", action="store_true", help="Do not start the dashboard HTTP server")
    ap.add_argument("--dashboard-port", type=int, default=DASHBOARD_PORT)
    args = ap.parse_args()

    STATE_DIR.mkdir(exist_ok=True)
    if args.stop:
        stop_processes()
        return 0
    if args.status:
        print_status()
        return 0

    stop_processes(quiet=True)
    anvil = start_anvil()
    wait_for_rpc(RPC_URL)
    addresses = deploy_contracts()
    mint_summary = None if args.skip_mint else mint_fixture(addresses)
    config = write_dashboard_config(addresses, mint_summary)
    build_palette_debug_reference()
    dashboard_proc = None if args.no_serve else start_dashboard(args.dashboard_port)
    write_state(anvil.pid, dashboard_proc.pid if dashboard_proc else None, config, args.dashboard_port)

    print("localhost run ready")
    print(f"  rpc:       {RPC_URL}")
    if dashboard_proc:
        print(f"  dashboard: http://127.0.0.1:{args.dashboard_port}/dashboard/")
    print(f"  config:    {DASHBOARD_CONFIG}")
    print(f"  state:     {STATE_FILE}")
    print(f"  anvil log: {ANVIL_LOG}")
    if dashboard_proc:
        print(f"  ui log:    {DASHBOARD_LOG}")
    print("  stop:      python3 tools/start_local_dashboard.py --stop")
    return 0


def start_anvil() -> subprocess.Popen[str]:
    log = ANVIL_LOG.open("w")
    cmd = [
        "anvil",
        "--host", "127.0.0.1",
        "--port", "8545",
        "--chain-id", str(CHAIN_ID),
    ]
    return subprocess.Popen(cmd, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)


def deploy_contracts() -> dict[str, str]:
    cmd = [
        "forge", "script", "script/DeployShadowPipeline.s.sol:DeployShadowPipeline",
        "--broadcast",
        "--rpc-url", RPC_URL,
        "--private-key", ANVIL_PROFILES[0]["evmPk"],
        "--slow",
    ]
    run(cmd, cwd=CONTRACTS)
    run_latest = CONTRACTS / "broadcast" / "DeployShadowPipeline.s.sol" / str(CHAIN_ID) / "run-latest.json"
    data = json.loads(run_latest.read_text())
    by_name: dict[str, str] = {}
    for tx in data.get("transactions", []):
        name = tx.get("contractName")
        addr = tx.get("contractAddress")
        if name and addr:
            by_name[name] = addr
    required = {
        "shadowToken": "ShadowToken",
        "featureNft": "FeatureNFT",
        "mintController": "ShadowMintController",
        "keyRegistry": "KeyRegistry",
    }
    missing = [name for name in required.values() if name not in by_name]
    if missing:
        raise SystemExit(f"deploy broadcast missing contract addresses for: {', '.join(missing)}")
    return {key: by_name[name] for key, name in required.items()}


def mint_fixture(addresses: dict[str, str]) -> dict[str, Any]:
    meta = json.loads((FIXTURE / "meta.json").read_text())
    env = os.environ.copy()
    env.update({
        "ST_ADDRESS": addresses["shadowToken"],
        "KR_ADDRESS": addresses["keyRegistry"],
        "MC_ADDRESS": addresses["mintController"],
        "FIX": "./test/fixtures/atomic_mint/atomic_mint_demo",
        "BEGIN_SUBMIT_COUNT": "1",
        "SUBMIT_CHUNK_SIZE": "3",
    })
    cmd = [
        "forge", "script", "script/MintOnSepolia.s.sol:MintOnSepolia",
        "--broadcast",
        "--rpc-url", RPC_URL,
        "--private-key", ANVIL_PROFILES[0]["evmPk"],
        "--slow",
    ]
    run(cmd, cwd=CONTRACTS, env=env)
    return {
        "fixture": "contracts/test/fixtures/atomic_mint/atomic_mint_demo",
        "shadowId": meta["shadow_id"],
        "imageCommit": meta["image_commit"],
    }


def write_dashboard_config(addresses: dict[str, str], mint_summary: dict[str, Any] | None) -> dict[str, Any]:
    owner_sk = owner_sk_from_seed("atomic_mint_demo")
    profiles = []
    for idx, p in enumerate(ANVIL_PROFILES):
        q = dict(p)
        if idx == 0:
            q["sk"] = hex32(owner_sk)
        else:
            q["sk"] = ""
        profiles.append(q)

    face_images = [
        {
            "label": "Fixture owner face preview (alice0)",
            "src": "../examples/faces/alice0.png",
            "fixture": "contracts/test/fixtures/atomic_mint/atomic_mint_demo",
            "imageCommit": mint_summary["imageCommit"] if mint_summary else None,
        },
        {"label": "Synthetic grid sample", "src": "../examples/faces/synthetic/grid_48/s101_neutral.png"},
        {"label": "Synthetic random sample", "src": "../examples/faces/synthetic/random_48/rand_0000.png"},
    ]
    config: dict[str, Any] = {
        "autoApply": True,
        "rpcUrl": RPC_URL,
        "chainId": CHAIN_ID,
        "fromBlock": 0,
        "contracts": addresses,
        "profiles": profiles,
        "minterFaceImages": face_images,
        "mintedFixture": mint_summary,
    }
    DASHBOARD_CONFIG.write_text(json.dumps(config, indent=2) + "\n")
    return config


def build_palette_debug_reference() -> None:
    run([sys.executable, "tools/build_palette_debug_reference.py"], cwd=REPO)


def start_dashboard(port: int) -> subprocess.Popen[str]:
    wait_for_port_free("127.0.0.1", port)
    log = DASHBOARD_LOG.open("w")
    cmd = [sys.executable, "-m", "http.server", str(port), "--directory", str(REPO)]
    return subprocess.Popen(cmd, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def wait_for_rpc(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    while time.time() < deadline:
        try:
            req = Request(url, data=payload, headers={"content-type": "application/json"})
            with urlopen(req, timeout=1) as res:
                if res.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise SystemExit(f"Anvil did not respond at {url}")


def wait_for_port_free(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex((host, port)) == 0:
            raise SystemExit(f"port {port} is already in use")


def write_state(anvil_pid: int, dashboard_pid: int | None, config: dict[str, Any], port: int) -> None:
    STATE_FILE.write_text(json.dumps({
        "anvilPid": anvil_pid,
        "dashboardPid": dashboard_pid,
        "dashboardPort": port,
        "rpcUrl": RPC_URL,
        "contracts": config["contracts"],
    }, indent=2) + "\n")


def stop_processes(quiet: bool = False) -> None:
    if not STATE_FILE.exists():
        if not quiet:
            print("no local dashboard state file")
        return
    state = json.loads(STATE_FILE.read_text())
    for key in ("dashboardPid", "anvilPid"):
        pid = state.get(key)
        if not pid:
            continue
        try:
            os.killpg(pid, signal.SIGTERM)
            if not quiet:
                print(f"stopped {key}={pid}")
        except ProcessLookupError:
            pass
        except PermissionError as err:
            print(f"could not stop {key}={pid}: {err}")
    STATE_FILE.unlink(missing_ok=True)


def print_status() -> None:
    if not STATE_FILE.exists():
        print("not running: no state file")
        return
    state = json.loads(STATE_FILE.read_text())
    for key in ("anvilPid", "dashboardPid"):
        pid = state.get(key)
        print(f"{key}: {pid} {'alive' if pid and pid_alive(pid) else 'not running'}")
    print(json.dumps(state, indent=2))


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def owner_sk_from_seed(seed: str) -> int:
    h = hashlib.sha256(b"OMP_ATOMIC_MINT_FIXTURE_v1:owner_sk:" + seed.encode()).digest()
    return (int.from_bytes(h, "big") % (GRUMPKIN_ORDER - 1)) + 1


def hex32(v: int) -> str:
    return "0x" + v.to_bytes(32, "big").hex()


if __name__ == "__main__":
    raise SystemExit(main())
