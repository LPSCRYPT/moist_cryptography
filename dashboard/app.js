import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  decodeFunctionResult,
  defineChain,
  encodeFunctionData,
  formatUnits,
  http,
  parseAbi,
} from "https://esm.sh/viem@2.31.0";
import { privateKeyToAccount } from "https://esm.sh/viem@2.31.0/accounts";
import { baseSepolia } from "https://esm.sh/viem@2.31.0/chains";
import { bytesHexToFields, decryptSlot, decodePlaintext } from "./crypto.js";

const DEFAULTS = {
  rpcUrl: "https://sepolia.base.org",
  chainId: "84532",
  fromBlock: "42673299",
  shadowToken: "0x15f8D237Cc15377a7C140617E2cfEEe39F49a91C",
  featureNft: "0x31ADA4c1E9837b336e7540B57F174417e04F42bA",
  mintController: "0x0fBCeb82555190011e5e0BA10D2265a852C2ED7c",
  keyRegistry: "0xffDb68f22Db0f9E63F739Cdf865541E3bA8bDE18",
};

const NAMED_PALETTES_23 = [
  ["amber", [[60,40,30],[100,65,35],[160,100,40],[220,170,70],[240,220,180],[40,25,15],[200,140,60],[140,115,75],[255,200,130],[15,8,5]]],
  ["moss", [[34,80,20],[60,120,40],[90,160,60],[140,200,80],[240,235,210],[180,140,80],[110,80,30],[200,160,40],[50,30,15],[25,60,15]]],
  ["bone", [[240,230,210],[220,210,190],[200,190,170],[180,170,150],[160,150,130],[140,130,110],[120,110,90],[100,90,70],[80,70,50],[60,50,30]]],
  ["ocean", [[5,10,25],[0,40,90],[0,80,140],[40,130,200],[80,180,220],[140,210,235],[220,240,250],[60,200,180],[0,30,70],[160,220,240]]],
  ["ember", [[236,85,38],[247,244,226],[158,187,193],[244,172,18],[30,27,30],[236,85,38],[247,244,226],[158,187,193],[30,27,30],[244,172,18]]],
  ["blood", [[238,0,0],[200,0,0],[160,0,0],[120,0,0],[80,0,0],[40,0,0],[255,50,50],[180,20,20],[100,0,0],[60,0,0]]],
  ["desert", [[200,120,80],[160,180,120],[240,220,180],[140,180,220],[100,60,40],[255,200,140],[80,100,70],[220,170,120],[240,240,230],[180,80,50]]],
  ["sunset", [[255,94,77],[255,140,66],[255,185,56],[255,220,80],[200,60,60],[230,100,50],[250,160,60],[255,200,70],[180,50,50],[210,80,45]]],
  ["jade", [[20,80,70],[40,140,120],[180,220,200],[200,140,120],[240,180,160],[255,250,240],[60,100,90],[180,90,80],[130,180,170],[10,40,35]]],
  ["tide", [[10,40,80],[30,90,140],[255,140,100],[240,200,160],[180,220,210],[255,255,240],[5,15,40],[90,160,180],[255,180,140],[50,80,110]]],
  ["peach", [[255,200,180],[255,160,140],[180,240,230],[255,240,220],[230,120,100],[60,140,140],[255,220,200],[255,255,245],[140,80,70],[40,90,100]]],
  ["gold", [[255,215,0],[200,165,0],[140,100,0],[40,30,5],[255,250,200],[60,80,140],[255,230,80],[180,140,40],[255,255,255],[90,60,15]]],
  ["storm", [[40,45,55],[100,110,125],[180,190,200],[255,255,80],[220,225,235],[15,15,25],[60,70,85],[140,150,170],[255,200,40],[5,5,15]]],
  ["midnight", [[15,10,40],[50,30,90],[90,60,140],[240,200,80],[255,240,200],[5,0,20],[140,100,200],[200,170,60],[40,20,70],[255,255,255]]],
  ["violet", [[100,40,160],[140,60,200],[180,80,240],[80,20,120],[60,10,100],[120,50,180],[160,70,220],[200,90,255],[90,30,140],[70,15,110]]],
  ["blush", [[255,182,193],[255,140,160],[220,90,120],[140,40,70],[255,240,235],[180,255,220],[255,200,210],[50,20,40],[255,80,140],[240,160,180]]],
  ["rust", [[183,65,14],[160,55,10],[140,45,8],[120,35,5],[100,28,3],[80,20,0],[200,80,20],[170,60,12],[130,40,6],[90,25,2]]],
  ["aurora", [[10,30,60],[60,255,160],[140,80,255],[255,80,180],[200,255,240],[40,160,180],[5,15,30],[255,255,200],[80,200,255],[100,40,140]]],
  ["ghost", [[250,250,255],[220,220,235],[180,170,200],[255,80,200],[110,90,140],[40,40,60],[200,180,220],[140,255,220],[90,70,110],[10,5,20]]],
  ["toxic", [[0,255,0],[200,255,0],[255,255,80],[255,0,200],[50,255,100],[255,80,255],[180,255,30],[0,0,0],[255,255,255],[10,40,5]]],
  ["acid", [[0,255,40],[255,255,0],[255,0,255],[0,0,0],[0,255,255],[180,255,40],[255,0,80],[40,0,80],[255,255,255],[255,140,0]]],
  ["neon", [[0,255,65],[255,0,110],[0,200,255],[255,255,0],[255,0,255],[0,255,200],[255,100,0],[100,0,255],[0,255,130],[255,50,180]]],
  ["void", [[5,5,15],[255,0,80],[80,255,80],[0,180,255],[40,5,40],[255,255,80],[20,20,30],[255,80,255],[140,140,160],[255,255,255]]],
].map(([name, rgb]) => ({ name, colors: rgb.map(([r, g, b]) => `#${[r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("")}`) }));

const DEFAULT_CALL_ABI = "function ownerOf(uint256 tokenId) view returns (address)";

const shadowAbi = parseAbi([
  "event ShadowMinted(uint256 indexed shadowId,address indexed minter,uint64 indexed mintIdx,bytes32 imageCommit)",
  "event ShadowSlotMutated(uint256 indexed shadowId,uint8 indexed slotIdx,bytes32 indexed originFaceId,uint256 featureId,uint16 mutationCount,bytes32 prevChainTip,bytes32 newChainTip,bytes c2)",
  "event ShadowSlotEnvelope(uint256 indexed shadowId,uint8 indexed slotIdx,bytes32 c1X,bytes32 c1Y)",
  "event SlotExtracted(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId,bytes32 finalLiveStateHash)",
  "event ShadowFeatureInserted(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId)",
  "event ShadowTransferred(uint256 indexed shadowId,address indexed to,bytes32 newEcdhPubX,bytes32 newEcdhPubY)",
  "event ShadowZIndexCommitSet(uint256 indexed shadowId,bytes32 newCommit)",
  "event ShadowDownscaleUpdated(uint256 indexed shadowId,uint64 indexed revision,bytes32 hi,bytes32 lo)",
  "event ShadowSlotRevealed(uint256 indexed shadowId,uint8 indexed slotIdx,uint256 indexed featureId,uint8 revealedRank)",
  "event ImageRegistered(bytes32 indexed imageCommit)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function shadowHeaderOf(uint256 shadowId) view returns (bytes32 ecdhPubX,bytes32 ecdhPubY,bool solved,bytes32 zIndexCommit)",
  "function slotOf(uint256 shadowId,uint8 slotIdx) view returns ((uint8 kind,uint256 featureId,bytes32 liveStateHash,uint16 mutationCount,bytes32 chainTip))",
  "function shadowT10(uint256,uint256) view returns (bytes32)",
  "function shadowDownscaleRevision(uint256) view returns (uint64)",
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
const state = { client: null, events: [], shadows: new Map(), selected: null, profiles: [], localConfig: null, localFixtureMeta: null, featurePalettes: new Map(), activeProfileIdx: 0 };

init();

async function init() {
  for (const [k, v] of Object.entries(DEFAULTS)) $(k).value = localStorage.getItem(`dash.${k}`) || v;
  state.profiles = JSON.parse(localStorage.getItem("dash.profiles") || "[]");
  if (state.profiles.length === 0) state.profiles.push({ label: "Owner", address: "", sk: "", evmPk: "" });
  state.activeProfileIdx = Number(localStorage.getItem("dash.activeProfileIdx") || "0");
  $("callerAbi").value = localStorage.getItem("dash.callerAbi") || DEFAULT_CALL_ABI;
  $("callerArgs").value = localStorage.getItem("dash.callerArgs") || "[\"1\"]";
  $("callerValue").value = localStorage.getItem("dash.callerValue") || "0";
  renderProfiles();
  wireCallerControls();
  updateSummary();
  $("addProfileBtn").onclick = () => { state.profiles.push({ label: "", address: "", sk: "", evmPk: "" }); state.activeProfileIdx = state.profiles.length - 1; saveProfiles(); renderProfiles(); refreshSelectedShadow(); };
  $("loadBtn").onclick = () => load().catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
  $("loadBtnSecondary").onclick = () => load().catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
  $("applyLocalBtn").onclick = () => applyLocalConfig().catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
  $("reloadLocalConfigBtn").onclick = () => loadLocalConfig(true).catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
  await loadLocalConfig(false);
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
    node.querySelector(".profileEvmPk").value = p.evmPk || "";
    node.querySelector(".profileLabel").oninput = (e) => updateProfile(idx, "label", e.target.value);
    node.querySelector(".profileAddress").oninput = (e) => updateProfile(idx, "address", e.target.value);
    node.querySelector(".profileSk").oninput = (e) => updateProfile(idx, "sk", e.target.value);
    node.querySelector(".profileEvmPk").oninput = (e) => updateProfile(idx, "evmPk", e.target.value);
    node.querySelector(".removeProfile").onclick = () => { state.profiles.splice(idx, 1); state.activeProfileIdx = Math.min(state.activeProfileIdx, Math.max(0, state.profiles.length - 1)); saveProfiles(); renderProfiles(); refreshSelectedShadow(); };
    root.appendChild(node);
  });
  renderCallerProfiles();
  renderActiveViewer();
}

function updateProfile(idx, key, value) {
  state.profiles[idx][key] = value.trim();
  saveProfiles();
  renderActiveViewer();
  renderCallerProfiles();
  refreshSelectedShadow();
}
function saveProfiles() {
  localStorage.setItem("dash.profiles", JSON.stringify(state.profiles));
  localStorage.setItem("dash.activeProfileIdx", String(state.activeProfileIdx));
}

function renderActiveViewer() {
  const select = $("activeViewer");
  if (!select) return;
  const previous = String(state.activeProfileIdx);
  select.textContent = "";
  state.profiles.forEach((p, idx) => {
    const opt = document.createElement("option");
    opt.value = String(idx);
    opt.textContent = profileLabel(p, idx);
    select.appendChild(opt);
  });
  if (state.activeProfileIdx >= state.profiles.length) state.activeProfileIdx = Math.max(0, state.profiles.length - 1);
  select.value = [...select.options].some((opt) => opt.value === previous) ? previous : String(state.activeProfileIdx);
  select.onchange = () => {
    state.activeProfileIdx = Number(select.value);
    saveProfiles();
    renderCallerProfiles();
    refreshSelectedShadow();
  };
}

function activeProfile() {
  return state.profiles[state.activeProfileIdx] || null;
}

function profileLabel(profile, idx) {
  return `${profile?.label || `User ${idx + 1}`}${profile?.address ? ` (${short(profile.address)})` : ""}`;
}

function refreshSelectedShadow() {
  if (state.selected != null && state.client) selectShadow(state.selected).catch((err) => setStatus(`ERROR: ${err.stack || err.message || err}`));
}

async function load() {
  for (const k of Object.keys(DEFAULTS)) localStorage.setItem(`dash.${k}`, $(k).value.trim());
  setStatus("Connecting to RPC…");
  const chain = dashboardChain();
  state.client = createPublicClient({ chain, transport: http($("rpcUrl").value.trim()) });
  const latest = await state.client.getBlockNumber();
  const fromBlock = BigInt($("fromBlock").value.trim() || "0");
  setStatus(`Connected to chain ${chain.id}. Latest block ${latest}. Fetching logs from ${fromBlock}…`);

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
  setStatus(`Loaded ${events.length} events across ${state.shadows.size} shadows. Select a shadow to inspect slots and T10 state-hash history.`);
  updateSummary(latest);
  renderShadowList();
  renderTimeline();
}

function dashboardChain() {
  const id = Number($("chainId").value.trim() || DEFAULTS.chainId);
  if (id === baseSepolia.id) return baseSepolia;
  return defineChain({
    id,
    name: id === 31337 ? "Anvil localhost" : `Custom chain ${id}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [$("rpcUrl").value.trim()] } },
  });
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

function updateSummary(latestBlock = null) {
  $("summaryRpc").textContent = $("rpcUrl")?.value?.trim() || "Not connected";
  $("summaryChain").textContent = `${$("chainId")?.value?.trim() || "-"}${latestBlock == null ? "" : ` · block ${latestBlock}`}`;
  $("summaryShadows").textContent = String(state.shadows.size);
  $("summaryEvents").textContent = String(state.events.length);
}

function buildShadowIndex() {
  state.shadows = new Map();
  state.featurePalettes = new Map();
  for (const ev of state.events) {
    if (ev.eventName === "FeaturePaletteRevealed") {
      state.featurePalettes.set(ev.args.featureId.toString(), {
        colors: parsePaletteRgbBytes(ev.args.paletteRGB),
        source: "FeaturePaletteRevealed event",
      });
    }

    const sid = eventShadowId(ev);
    if (sid == null) continue;
    const key = sid.toString();
    if (!state.shadows.has(key)) state.shadows.set(key, { shadowId: sid, events: [], slots: new Map(), minted: null, downscales: [] });
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
    if (ev.eventName === "ShadowSlotRevealed" || ev.eventName === "FeatureSlotRevealed") {
      const slot = Number(ev.args.slotIdx);
      const cur = s.slots.get(slot) || {};
      cur.revealed = true;
      cur.featureId = ev.args.featureId;
      if (ev.args.revealedRank != null) cur.revealedRank = ev.args.revealedRank;
      if (ev.args.plaintext && ev.args.plaintext !== "0x") cur.revealedPlaintext = ev.args.plaintext;
      s.slots.set(slot, cur);
    }
    if (ev.eventName === "ShadowDownscaleUpdated") {
      s.downscales.push({
        revision: ev.args.revision,
        hi: ev.args.hi,
        lo: ev.args.lo,
        blockNumber: ev.blockNumber,
        transactionHash: ev.transactionHash,
        logIndex: ev.logIndex,
      });
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
  root.classList.toggle("emptyState", state.shadows.size === 0);
  if (state.shadows.size === 0) {
    root.textContent = "No shadows found in the loaded block range.";
    return;
  }
  root.textContent = "";
  for (const s of state.shadows.values()) {
    const slotCount = s.slots.size;
    const revealedCount = [...s.slots.values()].filter((slot) => slot.revealed).length;
    const card = document.createElement("div");
    card.className = "shadowCard";
    card.innerHTML = `
      <div class="cardTitle">Shadow ${short(hexId(s.shadowId))}</div>
      <div class="hash small">${hexId(s.shadowId)}</div>
      <div class="pillRow">
        <span class="pill">${s.events.length} events</span>
        <span class="pill">${slotCount} touched slots</span>
        <span class="pill">${s.downscales.length} T10 revisions</span>
        ${revealedCount ? `<span class="pill okPill">${revealedCount} revealed</span>` : ""}
      </div>`;
    card.onclick = () => selectShadow(s.shadowId);
    root.appendChild(card);
  }
}

async function selectShadow(shadowId) {
  state.selected = shadowId;
  const s = state.shadows.get(shadowId.toString());
  const detail = await fetchShadowState(shadowId);
  renderShadowDetail(s, detail);
  applyCallPreset();
}

async function fetchShadowState(shadowId) {
  const st = $("shadowToken").value.trim();
  const calls = [];
  calls.push(call(st, shadowAbi, "ownerOf", [shadowId]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowHeaderOf", [shadowId]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowT10", [shadowId, 0n]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowT10", [shadowId, 1n]).catch(() => null));
  calls.push(call(st, shadowAbi, "shadowDownscaleRevision", [shadowId]).catch(() => null));
  for (let i = 0; i < 16; i++) calls.push(call(st, shadowAbi, "slotOf", [shadowId, i]).catch(() => null));
  const [owner, header, t10hi, t10lo, revision, ...slots] = await Promise.all(calls);
  return { owner, header, t10hi, t10lo, revision, slots };
}

async function call(address, abi, functionName, args) {
  const data = encodeFunctionData({ abi, functionName, args });
  const raw = await state.client.call({ to: address, data });
  return decodeFunctionResult({ abi, functionName, data: raw.data });
}

function renderShadowDetail(s, live) {
  const root = $("shadowDetail");
  const viewer = activeProfile();
  const header = live.header || [];
  root.innerHTML = `
    <div class="viewerPanel">
      <div>
        <div class="metricLabel">Viewing as</div>
        <div class="cardTitle">${escapeHtml(viewer ? profileLabel(viewer, state.activeProfileIdx) : "No active user")}</div>
      </div>
      <div class="small">Use the selector in “Test users” to switch whose keys are used for decryption and calls.</div>
    </div>
    <div class="kv">
      <div>shadowId</div><div class="hash">${hexId(s.shadowId)}</div>
      <div>owner</div><div class="hash">${live.owner || "unavailable"}</div>
      <div>solved</div><div>${header[2] ?? "unavailable"}</div>
      <div>zIndexCommit</div><div class="hash">${header[3] || "unavailable"}</div>
      <div>current T10 hi</div><div class="hash">${live.t10hi || "unavailable"}</div>
      <div>current T10 lo</div><div class="hash">${live.t10lo || "unavailable"}</div>
      <div>T10 revision</div><div>${live.revision ?? "unavailable"}</div>
    </div>
    <h3>Active viewer decrypted visual reconstruction</h3>
    ${activeViewerShadowHtml(s, live, viewer)}
    <h3>T10 state-hash history</h3>
    ${t10HistoryHtml(s.downscales)}
    <h3>Slots</h3>
    <div class="slots"></div>
  `;
  const slotsRoot = root.querySelector(".slots");
  for (let i = 0; i < 16; i++) {
    const eventSlot = s.slots.get(i) || {};
    const chainSlot = live.slots[i];
    const card = document.createElement("div");
    card.className = "slotCard";
    card.innerHTML = slotHtml(i, chainSlot, eventSlot, viewer);
    slotsRoot.appendChild(card);
  }
}

function t10HistoryHtml(downscales) {
  if (!downscales.length) return `<p class="small">No ShadowDownscaleUpdated events loaded for this shadow.</p>`;
  return `
    <p class="note">Current v2 T10 is an opaque state hash over hidden occupied slot commitments, not a raster BW image. The cards below are commitments for replay/indexing, not pixels.</p>
    <div class="downscaleHistory">${downscales.map((d) => `
      <div class="downscaleCard">
        <div class="small">rev ${d.revision} · block ${d.blockNumber} · tx ${short(d.transactionHash)}</div>
        <div class="metricLabel">T10 state hash</div>
        <div class="hash small">hi ${d.hi}<br>lo ${d.lo}</div>
      </div>`).join("")}</div>`;
}

function slotHtml(i, chainSlot, eventSlot, viewer) {
  const kind = chainSlot ? Number(chainSlot.kind) : -1;
  const kindName = ["EMPTY", "OCCUPIED", "REVEALED"][kind] || "unknown";
  const c2 = eventSlot.latestC2;
  const hasC2 = c2 && c2 !== "0x";
  const hasC1 = Boolean(eventSlot.c1X && eventSlot.c1Y);
  const activeDecrypt = viewer ? decryptStatus(viewer, c2, eventSlot) : `<div class="warn">No active viewer selected</div>`;
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
      <div>active viewer</div><div>${activeDecrypt}</div>
      <div>c1</div><div class="hash">${hasC1 ? `${eventSlot.c1X}<br>${eventSlot.c1Y}` : "missing"}</div>
    </div>
  `;
}

function activeViewerShadowHtml(s, live, viewer) {
  if (!viewer) return `<div class="emptyState">No active viewer selected.</div>`;
  const cards = [];
  const visualSlots = [];
  let decrypted = 0;
  let paletteReady = 0;
  for (let i = 0; i < 16; i++) {
    const eventSlot = s.slots.get(i) || {};
    const chainSlot = live.slots[i];
    const kind = chainSlot ? Number(chainSlot.kind) : -1;
    const result = slotDecodeResult(kind, viewer, eventSlot);
    const paletteInfo = result.decoded ? paletteForSlot(s, i, eventSlot) : null;
    if (result.ok && result.decoded && kind !== 2) decrypted++;
    if (result.decoded && paletteInfo?.colors) {
      paletteReady++;
      visualSlots.push({ slotIdx: i, kind, decoded: result.decoded, palette: paletteInfo.colors });
    }
    cards.push(`
      <div class="viewerSlot ${result.ok ? "viewerSlotOk" : "viewerSlotLocked"}">
        <div class="small">slot ${i} · ${["EMPTY", "OCCUPIED", "REVEALED"][kind] || "unknown"}</div>
        <div>${escapeHtml(result.status)}</div>
        ${result.decoded ? featurePreviewSvg(result.decoded, paletteInfo) : ""}
        ${result.decoded ? `<div class="small">x=${result.decoded.x} y=${result.decoded.y} scale=${result.decoded.scaleQ88}/256 turns=${result.decoded.quarterTurns} dims=${result.decoded.w}x${result.decoded.h}</div>` : ""}
        ${result.decoded ? `<div class="small">palette: ${escapeHtml(paletteInfo ? `${paletteInfo.label} · ${paletteInfo.source}` : "unavailable; showing no fake colors")}</div>` : ""}
      </div>`);
  }
  return `
    <div class="viewerSummary">
      <span class="pill okPill">${decrypted} decrypted hidden slots</span>
      <span class="pill ${paletteReady ? "okPill" : ""}">${paletteReady} palette-backed visual slots</span>
      <span class="pill">viewer ${escapeHtml(profileLabel(viewer, state.activeProfileIdx))}</span>
    </div>
    ${viewerVisualHtml(visualSlots)}
    <div class="viewerSlotGrid">${cards.join("")}</div>`;
}

function slotDecodeResult(kind, viewer, eventSlot) {
  if (kind === 2) {
    if (!eventSlot.revealedPlaintext) return { ok: true, status: "publicly revealed; plaintext event not loaded", decoded: null };
    try {
      return { ok: true, status: "publicly revealed", decoded: decodePlaintext(bytesHexToFields(eventSlot.revealedPlaintext)) };
    } catch (err) {
      return { ok: false, status: `revealed plaintext decode failed: ${err.message}` };
    }
  }
  return decryptForProfile(viewer, eventSlot.latestC2, eventSlot);
}

function decryptForProfile(profile, c2, eventSlot) {
  if (!profile?.sk) return { ok: false, status: "no decrypt key" };
  if (!c2 || c2 === "0x") return { ok: false, status: "no ciphertext" };
  if (!eventSlot.c1X || !eventSlot.c1Y) return { ok: false, status: "missing c1 envelope" };
  try {
    const fields = bytesHexToFields(c2);
    const { fields: plain } = decryptSlot(eventSlot.c1X, eventSlot.c1Y, fields, profile.sk);
    return { ok: true, status: "decrypted", decoded: decodePlaintext(plain) };
  } catch (err) {
    return { ok: false, status: `decrypt failed: ${err.message}` };
  }
}

function decryptStatus(profile, c2, eventSlot) {
  const label = profile.label || profile.address || "profile";
  const result = decryptForProfile(profile, c2, eventSlot);
  if (!result.ok) return `<div class="warn">${escapeHtml(label)}: ${escapeHtml(result.status)}</div>`;
  const decoded = result.decoded;
  return `<div class="ok">${escapeHtml(label)}: decrypted x=${decoded.x} y=${decoded.y} scale=${decoded.scaleQ88}/256 turns=${decoded.quarterTurns} dims=${decoded.w}x${decoded.h}</div>`;
}

function featurePreviewSvg(decoded, paletteInfo) {
  if (!decoded?.w || !decoded?.h || !decoded.indices?.length) return "";
  if (!paletteInfo?.colors) {
    return `<div class="warn small">Palette RGB unavailable. Decrypted indices are hidden correctly, but the dashboard will not invent colors.</div>${featureIndexMapSvg(decoded)}`;
  }
  const rects = decoded.indices.slice(0, decoded.w * decoded.h).map((idx, p) => {
    const x = p % decoded.w;
    const y = Math.floor(p / decoded.w);
    return `<rect x="${x}" y="${y}" width="1" height="1" fill="${paletteInfo.colors[idx & 0xf]}" />`;
  }).join("");
  return `<svg class="featurePreview" viewBox="0 0 ${decoded.w} ${decoded.h}" role="img" aria-label="palette-correct decrypted feature preview">${rects}</svg>`;
}

function featureIndexMapSvg(decoded) {
  const rects = decoded.indices.slice(0, decoded.w * decoded.h).map((idx, p) => {
    const x = p % decoded.w;
    const y = Math.floor(p / decoded.w);
    const level = Math.round(((idx & 0xf) / 15) * 255).toString(16).padStart(2, "0");
    return `<rect x="${x}" y="${y}" width="1" height="1" fill="#${level}${level}${level}" />`;
  }).join("");
  return `<svg class="featurePreview indexPreview" viewBox="0 0 ${decoded.w} ${decoded.h}" role="img" aria-label="palette index map, not final colors">${rects}</svg>`;
}

function paletteForSlot(shadow, slotIdx, eventSlot) {
  const featureId = eventSlot.featureId?.toString();
  if (featureId && state.featurePalettes.has(featureId)) return annotatePalette(state.featurePalettes.get(featureId));
  const fixtureShadow = state.localFixtureMeta?.shadow_id ? BigInt(state.localFixtureMeta.shadow_id).toString() : null;
  if (fixtureShadow && fixtureShadow === shadow.shadowId.toString() && Array.isArray(state.localFixtureMeta.palettes?.[slotIdx])) {
    return annotatePalette({
      colors: state.localFixtureMeta.palettes[slotIdx].map(rgbHexFromField),
      source: "local atomic_mint fixture palette",
    });
  }
  return null;
}

function annotatePalette(info) {
  if (!info?.colors) return info;
  const match = namedPaletteMatch(info.colors);
  return {
    ...info,
    namedPalette: match,
    label: match ? `${match} (canonical 23-palette set)` : "unknown non-canonical palette",
  };
}

function namedPaletteMatch(colors) {
  const normalized = colors.map((c) => c.toLowerCase());
  for (const pal of NAMED_PALETTES_23) {
    if (pal.colors.every((c, i) => normalized[i] === c)) return pal.name;
  }
  return null;
}

function rgbHexFromField(field) {
  const value = BigInt(field) & 0xffffffn;
  return `#${value.toString(16).padStart(6, "0")}`;
}

function parsePaletteRgbBytes(bytesHex) {
  const raw = (bytesHex || "").replace(/^0x/, "");
  const colors = [];
  for (let i = 0; i + 6 <= raw.length && colors.length < 10; i += 6) colors.push(`#${raw.slice(i, i + 6)}`);
  return colors;
}

function viewerVisualHtml(visualSlots) {
  if (!visualSlots.length) {
    return `<div class="emptyState">No palette-backed slot pixels are available for this viewer. Hidden slots need both decrypted indices and the real palette RGB table; the dashboard no longer fabricates colors.</div>`;
  }
  const hiddenCanvas = composeSlotsToCanvas(visualSlots.filter((slot) => slot.kind === 1));
  const allCanvas = composeSlotsToCanvas(visualSlots);
  return `
    <div class="visualPreviewGrid">
      <div>
        <div class="metricLabel">Viewer-local hidden color composite</div>
        ${canvasSvg(allCanvas, 48, "canvasPreview", "palette-correct local 48 by 48 feature composite")}
        <p class="small">Local reconstruction from decryptable/revealed slots with known palettes. This is not the on-chain T10 hash.</p>
      </div>
      <div>
        <div class="metricLabel">Viewer-local BW from hidden slots</div>
        ${bwSvgFromCanvas(hiddenCanvas)}
        <p class="small">Computed from hidden occupied slots only, matching the incremental-reveal visual rule when palettes are known.</p>
      </div>
    </div>`;
}

function composeSlotsToCanvas(slots) {
  const canvas = Array.from({ length: 48 * 48 }, () => null);
  for (const slot of [...slots].sort((a, b) => (a.kind === 2) - (b.kind === 2) || a.slotIdx - b.slotIdx)) drawSlot(canvas, slot.decoded, slot.palette);
  return canvas;
}

function drawSlot(canvas, decoded, palette) {
  const scale = decoded.scaleQ88 || 0;
  if (scale <= 0 || decoded.w <= 0 || decoded.h <= 0) return;
  const scaledW = Math.max(1, (decoded.w * scale + 255) >> 8);
  const scaledH = Math.max(1, (decoded.h * scale + 255) >> 8);
  const turns = decoded.quarterTurns & 3;
  const rotW = turns % 2 === 0 ? scaledW : scaledH;
  const rotH = turns % 2 === 0 ? scaledH : scaledW;
  const x0 = Math.floor((2 * decoded.x + scaledW - rotW) / 2);
  const y0 = Math.floor((2 * decoded.y + scaledH - rotH) / 2);
  for (let ry = 0; ry < rotH; ry++) {
    for (let rx = 0; rx < rotW; rx++) {
      const [sxScaled, syScaled] = unrotatePoint(rx, ry, scaledW, scaledH, turns);
      const sx = Math.min(decoded.w - 1, Math.floor((sxScaled * 256) / scale));
      const sy = Math.min(decoded.h - 1, Math.floor((syScaled * 256) / scale));
      const idx = decoded.indices[sy * decoded.w + sx] & 0xf;
      const dx = x0 + rx;
      const dy = y0 + ry;
      if (dx >= 0 && dx < 48 && dy >= 0 && dy < 48) canvas[dy * 48 + dx] = hexToRgb(palette[idx]);
    }
  }
}

function unrotatePoint(rx, ry, scaledW, scaledH, turns) {
  if (turns === 1) return [ry, scaledH - 1 - rx];
  if (turns === 2) return [scaledW - 1 - rx, scaledH - 1 - ry];
  if (turns === 3) return [scaledW - 1 - ry, rx];
  return [rx, ry];
}

function canvasSvg(canvas, size, className, label) {
  const rects = [];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const rgb = canvas[y * size + x];
      if (!rgb) continue;
      rects.push(`<rect x="${x}" y="${y}" width="1" height="1" fill="${rgbToHex(rgb)}" />`);
    }
  }
  return `<svg class="${className}" viewBox="0 0 ${size} ${size}" role="img" aria-label="${escapeHtml(label)}">${rects.join("")}</svg>`;
}

function bwSvgFromCanvas(canvas) {
  const cells = [];
  for (let by = 0; by < 16; by++) {
    for (let bx = 0; bx < 16; bx++) {
      let sum = 0;
      for (let dy = 0; dy < 3; dy++) {
        for (let dx = 0; dx < 3; dx++) {
          const rgb = canvas[(by * 3 + dy) * 48 + bx * 3 + dx];
          if (rgb) sum += Math.floor((77 * rgb[0] + 150 * rgb[1] + 29 * rgb[2]) / 256);
        }
      }
      const avg = Math.floor(sum / 9);
      const level = (avg > 64 ? 1 : 0) + (avg > 128 ? 1 : 0) + (avg > 192 ? 1 : 0);
      cells.push(level);
    }
  }
  const shades = ["#000000", "#757575", "#bababa", "#ffffff"];
  const rects = cells.map((level, idx) => `<rect x="${idx % 16}" y="${Math.floor(idx / 16)}" width="1" height="1" fill="${shades[level]}" />`).join("");
  return `<svg class="downscaleSvg" viewBox="0 0 16 16" role="img" aria-label="viewer-local BW downscale from decrypted hidden slots">${rects}</svg>`;
}

function hexToRgb(hex) {
  const raw = String(hex || "#000000").replace(/^#/, "0x");
  const value = Number(BigInt(raw) & 0xffffffn);
  return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

function rgbToHex(rgb) {
  return `#${rgb.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
}

async function loadLocalConfig(forceStatus) {
  try {
    const res = await fetch("./local.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    state.localConfig = await res.json();
    await loadLocalFixtureMetadata();
    renderMinterFixtures();
    if (forceStatus) setStatus(`Loaded dashboard/local.json${state.localFixtureMeta ? " and fixture palette metadata" : ""}. Click Apply localhost config to switch the dashboard to it.`);
    if (isLocalhost() && state.localConfig?.autoApply && !localStorage.getItem("dash.localApplied")) await applyLocalConfig();
  } catch (err) {
    state.localConfig = null;
    state.localFixtureMeta = null;
    renderMinterFixtures();
    if (forceStatus) setStatus(`No dashboard/local.json available (${err.message}). Run tools/start_local_dashboard.py first.`);
  }
}

async function loadLocalFixtureMetadata() {
  state.localFixtureMeta = null;
  const fixture = state.localConfig?.mintedFixture?.fixture || state.localConfig?.minterFaceImages?.find((face) => face.fixture)?.fixture;
  if (!fixture) return;
  try {
    const res = await fetch(`../${fixture}/meta.json`, { cache: "no-store" });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    state.localFixtureMeta = await res.json();
  } catch (err) {
    console.warn(`Could not load local fixture metadata for ${fixture}: ${err.message}`);
  }
}

async function applyLocalConfig() {
  if (!state.localConfig) await loadLocalConfig(false);
  const cfg = state.localConfig;
  if (!cfg) throw new Error("No local config loaded. Run tools/start_local_dashboard.py or place dashboard/local.json.");
  $("rpcUrl").value = cfg.rpcUrl || "http://127.0.0.1:8545";
  $("chainId").value = String(cfg.chainId || 31337);
  $("fromBlock").value = String(cfg.fromBlock ?? 0);
  for (const [key, inputId] of Object.entries({ shadowToken: "shadowToken", featureNft: "featureNft", mintController: "mintController", keyRegistry: "keyRegistry" })) {
    if (cfg.contracts?.[key]) $(inputId).value = cfg.contracts[key];
  }
  if (Array.isArray(cfg.profiles) && cfg.profiles.length) {
    state.profiles = cfg.profiles.map((p) => ({ label: p.label || "", address: p.address || "", sk: p.sk || "", evmPk: p.evmPk || "" }));
    saveProfiles();
    renderProfiles();
  }
  localStorage.setItem("dash.localApplied", "1");
  renderMinterFixtures();
  updateSummary();
  applyCallPreset();
  setStatus("Applied localhost config. Click Load / refresh to index the local chain.");
}

function renderMinterFixtures() {
  const root = $("minterFixtures");
  const faces = state.localConfig?.minterFaceImages || [];
  if (!faces.length) {
    root.textContent = "No local fixture config loaded.";
    return;
  }
  root.innerHTML = faces.map((face) => `
    <div class="faceCard">
      <img src="${escapeHtml(face.src)}" alt="${escapeHtml(face.label || "mint face")}" />
      <div class="small">${escapeHtml(face.label || face.src)}</div>
      <div class="pillRow"><span class="pill ${face.imageCommit ? "okPill" : ""}">${face.imageCommit ? "minted fixture" : "preview only"}</span></div>
      ${face.fixture ? `<div class="hash small">fixture ${escapeHtml(face.fixture)}</div>` : ""}
      ${face.imageCommit ? `<div class="hash small">imageCommit ${escapeHtml(face.imageCommit)}</div>` : ""}
    </div>`).join("");
}

function wireCallerControls() {
  $("knownContract").onchange = () => { updateCallerTarget(); applyCallPreset(); };
  $("callPreset").onchange = applyCallPreset;
  $("callerProfile").onchange = () => { state.activeProfileIdx = Number($("callerProfile").value || "0"); saveProfiles(); renderActiveViewer(); refreshSelectedShadow(); };
  $("callReadBtn").onclick = () => executeCaller(false).catch((err) => setCallerOutput(`ERROR: ${err.stack || err.message || err}`));
  $("callWriteBtn").onclick = () => executeCaller(true).catch((err) => setCallerOutput(`ERROR: ${err.stack || err.message || err}`));
  for (const id of ["callerAbi", "callerArgs", "callerValue"]) {
    $(id).oninput = () => localStorage.setItem(`dash.${id.replace("caller", "caller")}`, $(id).value);
  }
  updateCallerTarget();
  applyCallPreset();
}

function renderCallerProfiles() {
  const select = $("callerProfile");
  if (!select) return;
  select.textContent = "";
  state.profiles.forEach((p, idx) => {
    const opt = document.createElement("option");
    opt.value = String(idx);
    opt.textContent = profileLabel(p, idx);
    select.appendChild(opt);
  });
  if ([...select.options].some((opt) => opt.value === String(state.activeProfileIdx))) select.value = String(state.activeProfileIdx);
}

function updateCallerTarget() {
  const key = $("knownContract").value;
  if (key !== "custom") $("callerTarget").value = $(key).value.trim();
}

function applyCallPreset() {
  const preset = $("callPreset")?.value || "custom";
  if (preset === "custom") return;
  updateCallerTarget();
  const selectedShadow = state.selected != null ? state.selected.toString() : state.localConfig?.mintedFixture?.shadowId ? BigInt(state.localConfig.mintedFixture.shadowId).toString() : "1";
  const presets = {
    ownerOf: {
      contract: "shadowToken",
      abi: "function ownerOf(uint256 tokenId) view returns (address)",
      args: [selectedShadow],
    },
    downscaleRevision: {
      contract: "shadowToken",
      abi: "function shadowDownscaleRevision(uint256 shadowId) view returns (uint64)",
      args: [selectedShadow],
    },
    shadowHeader: {
      contract: "shadowToken",
      abi: "function shadowHeaderOf(uint256 shadowId) view returns (bytes32 ecdhPubX, bytes32 ecdhPubY, bool solved, bytes32 zIndexCommit)",
      args: [selectedShadow],
    },
    slotOf: {
      contract: "shadowToken",
      abi: "function slotOf(uint256 shadowId,uint8 slotIdx) view returns ((uint8 kind,uint256 featureId,bytes32 liveStateHash,uint16 mutationCount,bytes32 chainTip))",
      args: [selectedShadow, 0],
    },
  };
  const chosen = presets[preset];
  if (!chosen) return;
  $("knownContract").value = chosen.contract;
  updateCallerTarget();
  $("callerAbi").value = chosen.abi;
  $("callerArgs").value = JSON.stringify(chosen.args, null, 2);
  $("callerValue").value = "0";
}

async function executeCaller(sendTx) {
  if (!state.client) {
    const chain = dashboardChain();
    state.client = createPublicClient({ chain, transport: http($("rpcUrl").value.trim()) });
  }
  const abiItem = $("callerAbi").value.trim();
  const target = $("callerTarget").value.trim();
  const abi = parseAbi([abiItem]);
  const fn = abi.find((x) => x.type === "function");
  if (!fn) throw new Error("ABI item must be a function");
  const args = parseCallerArgs($("callerArgs").value.trim() || "[]");
  const data = encodeFunctionData({ abi, functionName: fn.name, args });
  localStorage.setItem("dash.callerAbi", abiItem);
  localStorage.setItem("dash.callerArgs", $("callerArgs").value);
  localStorage.setItem("dash.callerValue", $("callerValue").value);

  if (!sendTx || fn.stateMutability === "view" || fn.stateMutability === "pure") {
    const raw = await state.client.call({ to: target, data });
    const decoded = decodeFunctionResult({ abi, functionName: fn.name, data: raw.data });
    setCallerOutput(JSON.stringify(bigintJson(decoded), null, 2));
    return;
  }

  const profile = state.profiles[Number($("callerProfile").value || "0")];
  if (!profile?.evmPk) throw new Error("Selected profile has no EVM private key");
  const account = privateKeyToAccount(normalizeHex(profile.evmPk));
  const chain = dashboardChain();
  const wallet = createWalletClient({ account, chain, transport: http($("rpcUrl").value.trim()) });
  const value = BigInt($("callerValue").value.trim() || "0");
  const hash = await wallet.sendTransaction({ to: target, data, value });
  setCallerOutput(`tx ${hash}\nWaiting for receipt…`);
  const receipt = await state.client.waitForTransactionReceipt({ hash });
  setCallerOutput(JSON.stringify(bigintJson(receipt), null, 2));
}

function parseCallerArgs(raw) {
  return JSON.parse(raw, (_key, value) => {
    if (typeof value === "string" && /^-?[0-9]+$/.test(value)) return BigInt(value);
    return value;
  });
}

function normalizeHex(v) {
  const trimmed = String(v || "").trim();
  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

function isLocalhost() {
  return ["localhost", "127.0.0.1", "0.0.0.0"].includes(window.location.hostname);
}

function setCallerOutput(text) { $("callerOutput").textContent = text; }

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
