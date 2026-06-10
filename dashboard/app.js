import {
  createPublicClient,
  decodeEventLog,
  decodeFunctionResult,
  encodeFunctionData,
  formatUnits,
  http,
  parseAbi,
} from "https://esm.sh/viem@2.31.0";
import { baseSepolia } from "https://esm.sh/viem@2.31.0/chains";
import { bytesHexToFields, decryptSlot, decodePlaintext } from "./crypto.js";

const DEFAULTS = {
  rpcUrl: "https://sepolia.base.org",
  fromBlock: "0",
  shadowToken: "0x73a2bb3411B1a5D6f9df5a06d3b4bFBA95970e3d",
  featureNft: "0x6CfAD30a588a57946b306136D4094ca0c07f51aC",
  mintController: "0x68f777E5B1b8E6b1099F3d8D6153a7C5c9d19A9b",
  keyRegistry: "0x8c00dD1B1AA71099C9055942F22dB63Dc4361F9D",
};

const shadowAbi = parseAbi([
  "event ShadowMinted(uint256 indexed shadowId,address indexed minter,uint64 indexed mintIdx,bytes32 imageCommit)",
  "event ShadowSlotMutated(uint256 indexed shadowId,uint8 indexed slotIdx,bytes32 indexed originFaceId,uint256 featureId,uint16 mutationCount,bytes32 prevChainTip,bytes32 newChainTip,bytes c2)",
  "event ShadowSlotEnvelope(uint256 indexed shadowId,uint8 indexed slotIdx,bytes32 c1X,bytes32 c1Y)",
  "event SlotExtracted(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId,bytes32 finalLiveStateHash)",
  "event ShadowFeatureInserted(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId)",
  "event ShadowTransferred(uint256 indexed shadowId,address indexed to,bytes32 newEcdhPubX,bytes32 newEcdhPubY)",
  "event ShadowZIndexCommitSet(uint256 indexed shadowId,bytes32 newCommit)",
  "event ShadowT10Updated(uint256 indexed shadowId,bytes32 hi,bytes32 lo)",
  "event ShadowSlotRevealed(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId,uint8 revealedRank)",
  "event ImageRegistered(bytes32 indexed imageCommit)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function shadowHeaderOf(uint256 shadowId) view returns (bytes32 ecdhPubX,bytes32 ecdhPubY,bool solved,bytes32 zIndexCommit)",
  "function slotOf(uint256 shadowId,uint8 slotIdx) view returns ((uint8 kind,uint256 featureId,bytes32 liveStateHash,uint16 mutationCount,bytes32 chainTip))",
  "function shadowT10(uint256,uint256) view returns (bytes32)",
]);

const featureAbi = parseAbi([
  "event FeatureMinted(uint256 indexed featureId,uint256 indexed hostShadowId,uint8 indexed hostSlotIdx,address to,uint8 typeIdx,bytes32 originFaceId,bytes32 paletteCommit,bytes32 initialLiveStateHash)",
  "event FeaturePaletteSaltEnvelope(uint256 indexed featureId,bytes32 paletteSaltCt,bytes32 saltC1X,bytes32 saltC1Y)",
  "event FeaturePaletteRevealed(uint256 indexed featureId,bytes32 paletteCommit,bytes paletteRGB)",
  "event FeatureSlotRevealed(uint256 indexed featureId,uint256 indexed shadowId,uint8 indexed slotIdx,bytes plaintext)",
  "event FeatureTransferred(uint256 indexed featureId,address indexed to,bytes32 newLiveStateHashCheckpoint,bytes32 newC1X,bytes32 newC1Y,bytes c2)",
  "event FeatureExtracted(uint256 indexed featureId,uint256 indexed prevHostShadowId,uint8 indexed prevHostSlotIdx,bytes32 liveStateHashCheckpoint)",
  "event FeatureInserted(uint256 indexed featureId,uint256 indexed newHostShadowId,uint8 indexed newHostSlotIdx)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function featureOf(uint256 featureId) view returns ((uint8 typeIdx,bytes32 originFaceId,bytes32 paletteCommit,uint64 mintedAt,bytes32 liveStateHashCheckpoint,bool isInserted,uint256 hostShadowId,uint8 hostSlotIdx,bool paletteRevealed))",
]);

const mintControllerAbi = parseAbi([
  "event ShadowMintStarted(uint256 indexed shadowId,address indexed recipient,bytes32 indexed imageCommit)",
  "event MintCiphertextSubmitted(uint256 indexed shadowId,uint8 indexed slotIdx,bytes32 indexed ctCommit,bytes c2)",
]);

const $ = (id) => document.getElementById(id);
const state = { client: null, events: [], shadows: new Map(), selected: null, profiles: [] };

init();

function init() {
  for (const [k, v] of Object.entries(DEFAULTS)) $(k).value = localStorage.getItem(`dash.${k}`) || v;
  state.profiles = JSON.parse(localStorage.getItem("dash.profiles") || "[]");
  if (state.profiles.length === 0) state.profiles.push({ label: "Owner", address: "", sk: "" });
  renderProfiles();
  $("addProfileBtn").onclick = () => { state.profiles.push({ label: "", address: "", sk: "" }); renderProfiles(); };
  $("loadBtn").onclick = () => load().catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
}

function renderProfiles() {
  const root = $("profiles");
  root.textContent = "";
  const tpl = $("profileTemplate");
  state.profiles.forEach((p, idx) => {
    const node = tpl.content.cloneNode(true);
    node.querySelector(".profileLabel").value = p.label || "";
    node.querySelector(".profileAddress").value = p.address || "";
    node.querySelector(".profileSk").value = p.sk || "";
    node.querySelector(".profileLabel").oninput = (e) => updateProfile(idx, "label", e.target.value);
    node.querySelector(".profileAddress").oninput = (e) => updateProfile(idx, "address", e.target.value);
    node.querySelector(".profileSk").oninput = (e) => updateProfile(idx, "sk", e.target.value);
    node.querySelector(".removeProfile").onclick = () => { state.profiles.splice(idx, 1); saveProfiles(); renderProfiles(); };
    root.appendChild(node);
  });
}

function updateProfile(idx, key, value) {
  state.profiles[idx][key] = value.trim();
  saveProfiles();
}
function saveProfiles() { localStorage.setItem("dash.profiles", JSON.stringify(state.profiles)); }

async function load() {
  for (const k of Object.keys(DEFAULTS)) localStorage.setItem(`dash.${k}`, $(k).value.trim());
  setStatus("Connecting to RPC…");
  state.client = createPublicClient({ chain: baseSepolia, transport: http($("rpcUrl").value.trim()) });
  const latest = await state.client.getBlockNumber();
  const fromBlock = BigInt($("fromBlock").value.trim() || "0");
  setStatus(`Connected. Latest block ${latest}. Fetching logs from ${fromBlock}…`);

  const addresses = {
    st: $("shadowToken").value.trim(),
    fn: $("featureNft").value.trim(),
    mc: $("mintController").value.trim(),
  };
  const events = [];
  events.push(...await readEvents(addresses.st, shadowAbi, fromBlock, latest));
  events.push(...await readEvents(addresses.fn, featureAbi, fromBlock, latest));
  events.push(...await readEvents(addresses.mc, mintControllerAbi, fromBlock, latest));
  events.sort((a, b) => Number(a.blockNumber - b.blockNumber) || a.transactionIndex - b.transactionIndex || a.logIndex - b.logIndex);
  state.events = events;
  buildShadowIndex();
  setStatus(`Loaded ${events.length} events across ${state.shadows.size} shadows. Fetching live selected state on demand.`);
  renderShadowList();
  renderTimeline();
}

async function readEvents(address, abi, fromBlock, toBlock) {
  const names = abi.filter((x) => x.type === "event").map((x) => x.name);
  const out = [];
  const step = 50_000n;
  for (const name of names) {
    for (let start = fromBlock; start <= toBlock; start += step + 1n) {
      const end = start + step > toBlock ? toBlock : start + step;
      const logs = await state.client.getLogs({ address, event: abi.find((x) => x.type === "event" && x.name === name), fromBlock: start, toBlock: end });
      for (const log of logs) out.push({ ...log, contract: address, eventName: name, args: log.args });
    }
  }
  return out;
}

function buildShadowIndex() {
  state.shadows = new Map();
  for (const ev of state.events) {
    const sid = eventShadowId(ev);
    if (sid == null) continue;
    const key = sid.toString();
    if (!state.shadows.has(key)) state.shadows.set(key, { shadowId: sid, events: [], slots: new Map(), minted: null });
    const s = state.shadows.get(key);
    s.events.push(ev);
    if (ev.eventName === "ShadowMinted") s.minted = ev;
    if (ev.eventName === "ShadowSlotMutated" || ev.eventName === "MintCiphertextSubmitted") {
      const slot = Number(ev.args.slotIdx);
      const cur = s.slots.get(slot) || {};
      // Mint finalization emits ShadowSlotMutated with empty c2 because the
      // real ciphertext was submitted to the mint controller earlier. Do not
      // let that bookkeeping event overwrite the submitted decryptable c2.
      if (ev.args.c2 && ev.args.c2 !== "0x") {
        cur.latestC2 = ev.args.c2;
        cur.latestC2Event = ev;
      }
      if (ev.args.featureId != null) cur.featureId = ev.args.featureId;
      s.slots.set(slot, cur);
    }
    if (ev.eventName === "ShadowSlotEnvelope") {
      const slot = Number(ev.args.slotIdx);
      const cur = s.slots.get(slot) || {};
      cur.c1X = ev.args.c1X;
      cur.c1Y = ev.args.c1Y;
      cur.c1Event = ev;
      s.slots.set(slot, cur);
    }
    if (ev.eventName === "ShadowSlotRevealed") {
      const slot = Number(ev.args.slotIdx);
      const cur = s.slots.get(slot) || {};
      cur.revealed = true;
      cur.featureId = ev.args.featureId;
      cur.revealedRank = ev.args.revealedRank;
      s.slots.set(slot, cur);
    }
  }
}

function eventShadowId(ev) {
  if (ev.args.shadowId != null) return ev.args.shadowId;
  if (ev.args.hostShadowId != null) return ev.args.hostShadowId;
  if (ev.args.prevHostShadowId != null) return ev.args.prevHostShadowId;
  if (ev.args.newHostShadowId != null) return ev.args.newHostShadowId;
  return null;
}

function renderShadowList() {
  const root = $("shadowList");
  root.textContent = "";
  for (const s of state.shadows.values()) {
    const card = document.createElement("div");
    card.className = "shadowCard";
    card.innerHTML = `<div class="hash">${hexId(s.shadowId)}</div><div class="small">${s.events.length} events</div>`;
    card.onclick = () => selectShadow(s.shadowId);
    root.appendChild(card);
  }
}

async function selectShadow(shadowId) {
  state.selected = shadowId;
  const s = state.shadows.get(shadowId.toString());
  const detail = await fetchShadowState(shadowId);
  renderShadowDetail(s, detail);
}

async function fetchShadowState(shadowId) {
  const st = $("shadowToken").value.trim();
  const calls = [];
  calls.push(call(st, shadowAbi, "ownerOf", [shadowId]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowHeaderOf", [shadowId]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowT10", [shadowId, 0n]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowT10", [shadowId, 1n]).catch(() => null));
  for (let i = 0; i < 16; i++) calls.push(call(st, shadowAbi, "slotOf", [shadowId, i]).catch(() => null));
  const [owner, header, t10hi, t10lo, ...slots] = await Promise.all(calls);
  return { owner, header, t10hi, t10lo, slots };
}

async function call(address, abi, functionName, args) {
  const data = encodeFunctionData({ abi, functionName, args });
  const raw = await state.client.call({ to: address, data });
  return decodeFunctionResult({ abi, functionName, data: raw.data });
}

function renderShadowDetail(s, live) {
  const root = $("shadowDetail");
  const profiles = state.profiles.filter((p) => p.address || p.sk);
  const header = live.header || [];
  root.innerHTML = `
    <div class="kv">
      <div>shadowId</div><div class="hash">${hexId(s.shadowId)}</div>
      <div>owner</div><div class="hash">${live.owner || "unavailable"}</div>
      <div>solved</div><div>${header[2] ?? "unavailable"}</div>
      <div>zIndexCommit</div><div class="hash">${header[3] || "unavailable"}</div>
      <div>T10 hi</div><div class="hash">${live.t10hi || "unavailable"}</div>
      <div>T10 lo</div><div class="hash">${live.t10lo || "unavailable"}</div>
    </div>
    <h3>Slots</h3>
    <div class="slots"></div>
  `;
  const slotsRoot = root.querySelector(".slots");
  for (let i = 0; i < 16; i++) {
    const eventSlot = s.slots.get(i) || {};
    const chainSlot = live.slots[i];
    const card = document.createElement("div");
    card.className = "slotCard";
    card.innerHTML = slotHtml(i, chainSlot, eventSlot, profiles);
    slotsRoot.appendChild(card);
  }
}

function slotHtml(i, chainSlot, eventSlot, profiles) {
  const kind = chainSlot ? Number(chainSlot.kind) : -1;
  const kindName = ["EMPTY", "OCCUPIED", "REVEALED"][kind] || "unknown";
  const c2 = eventSlot.latestC2;
  const hasC2 = c2 && c2 !== "0x";
  const hasC1 = Boolean(eventSlot.c1X && eventSlot.c1Y);
  const decryptRows = profiles.map((p) => decryptStatus(p, c2, eventSlot)).join("");
  const availability = kind === 2
    ? `<span class="ok">public revealed slot</span>`
    : hasC2 && hasC1
      ? `<span class="ok">ciphertext + c1 available</span>`
      : hasC2
        ? `<span class="bad">ciphertext present, c1 missing from chain events</span>`
        : `<span class="warn">no ciphertext event for current slot state</span>`;
  return `
    <h3>Slot ${i}: ${kindName}</h3>
    <div class="kv">
      <div>featureId</div><div class="hash">${chainSlot?.featureId ?? eventSlot.featureId ?? "-"}</div>
      <div>mutationCount</div><div>${chainSlot?.mutationCount ?? "-"}</div>
      <div>liveStateHash</div><div class="hash">${chainSlot?.liveStateHash ?? "-"}</div>
      <div>availability</div><div>${availability}</div>
      <div>c1</div><div class="hash">${hasC1 ? `${eventSlot.c1X}<br>${eventSlot.c1Y}` : "missing"}</div>
    </div>
    ${decryptRows ? `<div class="small">${decryptRows}</div>` : ""}
  `;
}

function decryptStatus(profile, c2, eventSlot) {
  const label = profile.label || profile.address || "profile";
  if (!profile.sk) return `<div>${escapeHtml(label)}: no Grumpkin sk configured</div>`;
  if (!c2 || c2 === "0x") return `<div>${escapeHtml(label)}: no ciphertext</div>`;
  if (!eventSlot.c1X || !eventSlot.c1Y) return `<div class="bad">${escapeHtml(label)}: cannot decrypt from chain-only data; c1 is missing</div>`;
  try {
    const fields = bytesHexToFields(c2);
    const { fields: plain } = decryptSlot(eventSlot.c1X, eventSlot.c1Y, fields, profile.sk);
    const decoded = decodePlaintext(plain);
    return `<div class="ok">${escapeHtml(label)}: decrypted pose x=${decoded.x} y=${decoded.y} scale=${decoded.scaleQ88}/256 turns=${decoded.quarterTurns} dims=${decoded.w}x${decoded.h}</div>`;
  } catch (err) {
    return `<div class="warn">${escapeHtml(label)}: decrypt failed (${escapeHtml(err.message)})</div>`;
  }
}

function renderTimeline() {
  const root = $("timeline");
  root.textContent = "";
  for (const ev of state.events.slice(-300)) {
    const card = document.createElement("div");
    card.className = "eventCard";
    card.innerHTML = `<strong>${ev.eventName}</strong> <span class="small">block ${ev.blockNumber} tx ${short(ev.transactionHash)}</span><pre>${escapeHtml(JSON.stringify(bigintJson(ev.args), null, 2))}</pre>`;
    root.appendChild(card);
  }
}

function bigintJson(v) {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(bigintJson);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, bigintJson(val)]));
  return v;
}

function setStatus(text) { $("status").textContent = text; }
function hexId(v) { return `0x${BigInt(v).toString(16).padStart(64, "0")}`; }
function short(v) { return v ? `${v.slice(0, 10)}…${v.slice(-6)}` : ""; }
function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
