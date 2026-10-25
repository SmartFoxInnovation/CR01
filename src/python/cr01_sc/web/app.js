"use strict";

const appState = {
  snapshot: null,
  actionToken: null,
  bearerToken: sessionStorage.getItem("cr01_showcase_bearer") || "",
  requiresBearer: false,
  activeComplexity: null,
};

const byId = (id) => document.getElementById(id);

function node(tag, className = "", text = null) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== null) item.textContent = String(text);
  return item;
}

function empty(item) {
  while (item.firstChild) item.removeChild(item.firstChild);
}

function appendTextList(target, values) {
  empty(target);
  values.forEach((value) => target.appendChild(node("li", "", value)));
}

class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message || `Request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code || "request_failed";
  }
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (appState.bearerToken) headers.set("Authorization", `Bearer ${appState.bearerToken}`);
  if (options.action) headers.set("X-CR01-Action-Token", appState.actionToken || "");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  let body = null;
  try {
    body = await response.json();
  } catch (_) {
    body = null;
  }
  if (!response.ok) throw new ApiError(response.status, body);
  return body;
}

async function connect() {
  const session = await apiFetch("/api/v1/session");
  appState.actionToken = session.action_token;
  appState.requiresBearer = Boolean(session.bearer_required);
  byId("access-button").classList.toggle("hidden", !appState.requiresBearer);
  const snapshot = await apiFetch("/api/v1/status");
  appState.snapshot = snapshot;
  renderSnapshot(snapshot);
  document.body.dataset.ready = "true";
  byId("rail-status").textContent = snapshot.product.status === "evidence-ready" ? "Evidence online" : "Partial evidence";
}

function renderSnapshot(snapshot) {
  byId("product-label").textContent = `CR01-SC ${snapshot.product.version}`;
  const generated = new Date(snapshot.generated_at);
  byId("snapshot-time").textContent = `Snapshot ${generated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  byId("quantum-short-claim").textContent = snapshot.quantum_readiness.short_claim;
  byId("report-health").textContent = `${snapshot.report_health.available} / ${snapshot.report_health.expected} reports`;
  renderHeadline(snapshot.headline);
  renderProtocol(snapshot.protocol_layers);
  renderEvidence(snapshot.evidence_families, snapshot.sources);
  renderPerformance(snapshot.performance);
  renderLifecycle(snapshot.lifecycle);
  renderComplexity(snapshot.complexity);
  renderQuantum(snapshot.quantum_readiness);
  renderEnterprise(snapshot.enterprise, snapshot.maturity);
}

function renderHeadline(metrics) {
  const target = byId("headline-metrics");
  empty(target);
  metrics.forEach((metric) => {
    const item = node("article", `metric-item ${metric.tone || "neutral"}`);
    const unavailable = metric.value === "unavailable";
    item.append(
      node("strong", "", unavailable ? "—" : metric.value),
      node("span", "", metric.label),
      node("small", "", unavailable ? "Report unavailable" : metric.qualifier),
    );
    target.appendChild(item);
  });
}

function renderProtocol(layers) {
  const target = byId("protocol-flow");
  empty(target);
  layers.forEach((layer) => {
    const item = node("article", "protocol-item");
    item.append(
      node("span", "step", layer.step),
      node("h3", "", layer.name),
      node("span", "primitive", layer.primitive),
      node("p", "", layer.purpose),
      node("span", "flow-arrow", "→"),
    );
    target.appendChild(item);
  });
}

function renderEvidence(families, sources) {
  const target = byId("evidence-table");
  empty(target);
  families.forEach((family, index) => {
    const row = node("div", "evidence-row");
    row.setAttribute("role", "row");
    const name = node("div", "evidence-name");
    name.append(node("strong", "", family.label), node("small", "", family.source));
    const status = node("div", "evidence-state");
    status.appendChild(node("span", `state-chip ${family.status}`, family.status));
    const copy = node("div", "evidence-copy");
    copy.appendChild(node("span", "", family.description));
    row.append(
      node("span", "evidence-index", String(index + 1).padStart(2, "0")),
      name,
      node("strong", "evidence-result", family.result === "unavailable" ? "—" : family.result),
      copy,
      status,
    );
    target.appendChild(row);
  });

  const sourceTarget = byId("source-list");
  empty(sourceTarget);
  sources.forEach((source) => {
    const item = node("div", "source-item");
    const path = node("code", "", source.path);
    const modified = node("span", "", source.run_at ? new Date(source.run_at).toLocaleString() : source.error || "missing");
    const digest = node("code", "", source.sha256 ? `sha256:${source.sha256}` : "no digest");
    item.append(path, modified, digest);
    sourceTarget.appendChild(item);
  });
}

function renderPerformance(performance) {
  byId("performance-context").textContent = `${performance.payload_bytes || "—"} bytes · median of ${formatInteger(performance.repeats)} run means · seal + authenticated receive`;
  const target = byId("latency-chart");
  empty(target);
  const available = performance.rows.filter((row) => row.available && Number.isFinite(Number(row.round_trip_ms)));
  if (!available.length) {
    target.appendChild(node("p", "", "Native performance report unavailable."));
    return;
  }
  const values = available.map((row) => Number(row.round_trip_ms));
  const low = Math.min(...values);
  const high = Math.max(...values);
  const logLow = Math.log(low);
  const logRange = Math.max(Math.log(high) - logLow, 0.000001);

  available.forEach((row) => {
    const wrapper = node("div", `latency-row ${row.role}`);
    const label = node("div", "latency-label");
    label.append(node("strong", "", row.label), node("small", "", `${formatInteger(row.overhead_bytes)} B overhead`));
    const track = node("div", "bar-track");
    const fill = node("span", "bar-value");
    const normalized = (Math.log(Number(row.round_trip_ms)) - logLow) / logRange;
    fill.style.width = `${Math.max(2, 9 + normalized * 91)}%`;
    track.appendChild(fill);
    const number = node("div", "latency-number");
    number.append(node("strong", "", `${Number(row.round_trip_ms).toFixed(4)} ms`), node("small", "", `${formatInteger(row.messages_per_second)} pairs/s`));
    wrapper.append(label, track, number);
    target.appendChild(wrapper);
  });

  const cr01 = available.find((row) => row.role === "cr01");
  byId("cr01-throughput").textContent = cr01 ? compactNumber(cr01.messages_per_second) : "—";
}

function renderLifecycle(lifecycle) {
  const target = byId("lifecycle-measurements");
  empty(target);
  if (!lifecycle || lifecycle.rows.length !== 4) {
    target.appendChild(node("p", "microcopy", "Lifecycle measurements unavailable or source-stale."));
    return;
  }
  lifecycle.rows.forEach((item) => {
    const row = node("div", "lifecycle-row");
    const label = node("div");
    label.append(node("strong", "", item.label), node("small", "", item.boundary));
    row.append(label, node("strong", "", `${Number(item.milliseconds).toFixed(3)} ms`));
    target.appendChild(row);
  });
}

function renderComplexity(complexity) {
  appState.activeComplexity = complexity.default_id;
  const tabs = byId("complexity-tabs");
  empty(tabs);
  complexity.items.forEach((item) => {
    const button = node("button", "complexity-tab", item.name);
    button.type = "button";
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", String(item.id === appState.activeComplexity));
    button.dataset.complexityId = item.id;
    button.addEventListener("click", () => {
      appState.activeComplexity = item.id;
      tabs.querySelectorAll("button").forEach((tab) => tab.setAttribute("aria-selected", String(tab === button)));
      renderComplexityItem(item);
    });
    tabs.appendChild(button);
  });
  renderComplexityItem(complexity.items.find((item) => item.id === appState.activeComplexity));
}

function renderComplexityItem(item) {
  const target = byId("complexity-stage");
  empty(target);
  if (!item) return;

  const copy = node("div", "complexity-copy");
  const statusClass = item.status.includes("vulnerable") ? " quantum-vulnerable" : "";
  copy.append(
    node("span", `component-status${statusClass}`, item.status),
    node("h3", "", item.name),
    node("span", "component-role", item.role),
  );
  const notes = node("ul", "complexity-notes");
  item.notes.forEach((noteText) => notes.appendChild(node("li", "", noteText)));
  copy.appendChild(notes);

  const visual = node("div", "complexity-visual");
  if (item.id === "aes256-context") renderKeyspaceVisual(visual, item);
  else if (item.id === "mlkem768") renderLatticeVisual(visual, item);
  else if (item.id === "mldsa65") renderSignatureVisual(visual, item);
  target.append(copy, visual);
}

function renderKeyspaceVisual(target, item) {
  target.append(node("strong", "keyspace-value", item.primary.expression), node("span", "keyspace-science", `≈ ${item.primary.scientific} possible keys`));
  const grid = node("div", "keyspace-grid");
  for (let i = 0; i < 64; i += 1) grid.appendChild(node("span"));
  target.appendChild(grid);
  const compare = node("div", "model-comparison");
  const classical = node("div");
  classical.append(node("small", "", "classical exhaustive search"), node("strong", "", item.primary.expression));
  const quantum = node("div");
  quantum.append(node("small", "", item.quantum_label), node("strong", "", item.quantum_model.expression));
  compare.append(classical, quantum);
  target.appendChild(compare);
}

function renderLatticeVisual(target, item) {
  const field = node("div", "lattice-field");
  for (let i = 0; i < 49; i += 1) field.appendChild(node("span"));
  target.appendChild(field);
  const readout = node("div", "parameter-readout");
  readout.append(
    parameterBlock("PARAMETER", "768"),
    parameterBlock("CIPHERTEXT", item.ciphertext_bytes ? `${item.ciphertext_bytes} B` : "—"),
    parameterBlock("STANDARD", "FIPS 203"),
  );
  target.appendChild(readout);
}

function renderSignatureVisual(target, item) {
  const bars = node("div", "signature-bars");
  for (let i = 0; i < 28; i += 1) {
    const bar = node("span");
    bar.style.height = `${35 + ((i * 37) % 65)}%`;
    bars.appendChild(bar);
  }
  target.appendChild(bars);
  const readout = node("div", "parameter-readout");
  readout.append(
    parameterBlock("PARAMETER", "65"),
    parameterBlock("SIGNATURE", item.signature_bytes ? `${item.signature_bytes} B` : "—"),
    parameterBlock("STANDARD", "FIPS 204"),
  );
  target.appendChild(readout);
}

function parameterBlock(label, value) {
  const block = node("div");
  block.append(node("strong", "", value), node("small", "", label));
  return block;
}

function renderQuantum(quantum) {
  byId("quantum-headline").textContent = quantum.headline;
  appendTextList(byId("quantum-why"), quantum.why);
  appendTextList(byId("quantum-not"), quantum.not_claimed);

  const gates = byId("quantum-gates");
  empty(gates);
  quantum.gates.forEach((gate, index) => {
    const item = node("div", "gate-item");
    item.append(node("span", "gate-number", String(index + 1).padStart(2, "0")), node("strong", "", gate.name));
    const state = node("span", `gate-state ${gate.state === "complete" ? "complete" : ""}`, gate.state);
    item.append(state, node("small", "gate-owner", gate.owner));
    gates.appendChild(item);
  });

  const standards = byId("standards-row");
  empty(standards);
  quantum.standards.forEach((standard) => {
    const link = node("a", "standard-link");
    link.href = standard.url;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    const copy = node("div");
    copy.append(node("strong", "", standard.name), node("small", "", standard.status));
    link.append(node("strong", "", standard.id), copy, node("span", "", "↗"));
    standards.appendChild(link);
  });
}

function renderEnterprise(enterprise, maturity) {
  const path = byId("deployment-path");
  empty(path);
  enterprise.deployment_profiles.forEach((profile, index) => {
    const item = node("article", "deployment-item");
    item.append(
      node("span", "deployment-number", `0${index + 1}`),
      node("h3", "", profile.name),
      node("p", "", profile.fit),
      node("div", "deployment-controls", profile.controls),
    );
    path.appendChild(item);
  });

  appendTextList(byId("evaluation-assets"), enterprise.evaluation_assets);
  const maturityTarget = byId("maturity-list");
  empty(maturityTarget);
  maturity.forEach((entry) => {
    const item = node("div", `maturity-item ${entry.tone}`);
    item.append(node("span", "", entry.use), node("strong", "", entry.state));
    maturityTarget.appendChild(item);
  });
}

function startStepAnimation() {
  const steps = [...document.querySelectorAll("[data-live-step]")];
  steps.forEach((step) => step.classList.remove("running", "pass"));
  let cursor = 0;
  steps[0]?.classList.add("running");
  const timer = window.setInterval(() => {
    if (cursor < steps.length) {
      steps[cursor].classList.remove("running");
    }
    cursor += 1;
    if (cursor < steps.length) steps[cursor].classList.add("running");
  }, 430);
  return {
    pass() {
      window.clearInterval(timer);
      steps.forEach((step) => { step.classList.remove("running"); step.classList.add("pass"); });
    },
    fail() {
      window.clearInterval(timer);
      steps.forEach((step) => step.classList.remove("running", "pass"));
    },
  };
}

async function runProof() {
  const button = byId("run-proof");
  const seed = Number(byId("demo-seed").value);
  if (!Number.isInteger(seed) || seed < 0 || seed > 2147483647) {
    showToast("Request id must be an integer from 0 to 2147483647.", true);
    return;
  }
  button.disabled = true;
  button.firstChild.textContent = "Validation running ";
  document.body.dataset.validation = "running";
  byId("proof-status").textContent = "Starting native C++ peers";
  empty(byId("proof-output"));
  byId("proof-duration").textContent = "running";
  byId("proof-run-id").textContent = `REQ-${seed}`;
  const animation = startStepAnimation();
  try {
    const result = await apiFetch("/api/v1/validate", {
      method: "POST",
      action: true,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ seed }),
    });
    if (result.summary.status === "pass") animation.pass(); else animation.fail();
    document.body.dataset.validation = result.summary.status === "pass" ? "pass" : "error";
    byId("proof-status").textContent = `${result.summary.passed_checks} / ${result.summary.total_checks} native checks passed`;
    byId("proof-duration").textContent = `${Number(result.summary.duration_ms).toFixed(1)} ms`;
    renderProofOutput(result);
    showToast("Validation complete.");
  } catch (error) {
    animation.fail();
    document.body.dataset.validation = "error";
    byId("proof-status").textContent = error.code === "native_engine_unavailable" ? "C++ engine unavailable — build required" : "Validation did not complete";
    byId("proof-duration").textContent = "— ms";
    const failure = node("div", "idle-output");
    failure.append(node("strong", "", "No successful live result."), node("p", "", error.message || "Live validation failed."));
    empty(byId("proof-output"));
    byId("proof-output").appendChild(failure);
    if (error instanceof ApiError && error.status === 401) openAccessDialog();
    showToast(error.message || "Live validation failed.", true);
  } finally {
    button.disabled = false;
    button.firstChild.textContent = "Run live validation ";
  }
}

function renderProofOutput(result) {
  const target = byId("proof-output");
  empty(target);
  const summary = node("div", "validation-summary");
  const ring = node("span", "summary-ring", `${result.summary.passed_checks}/${result.summary.total_checks}`);
  const summaryCopy = node("div");
  summaryCopy.appendChild(node("strong", "", result.summary.status === "pass" ? "Session established. Checks passed." : "Some checks did not pass."));
  summary.append(ring, summaryCopy);
  target.appendChild(summary);

  const transcript = result.handshake.transcript || {};
  addTerminalGroup(target, "Native C++ engine", [
    ["transport", result.engine.transport],
    ["OpenSSL", result.engine.openssl.join(", ")],
    ["executable SHA-256", shortHash(result.engine.executable_sha256)],
    ["peer processes", result.engine.native_peer_processes],
  ]);
  addTerminalGroup(target, "V2 channel", [
    ["initiator identity", shortHash(transcript.identity_pins?.initiator_sha256)],
    ["responder identity", shortHash(transcript.identity_pins?.responder_sha256)],
    ["session id", transcript.records?.session_id],
    ["restart policy", result.handshake.summary?.restart_policy],
  ]);
  addTerminalGroup(target, "Authenticated flights", Object.entries(transcript.flights || {}).map(
    ([name, frame]) => [humanize(name), `${frame.bytes} B · ${shortHash(frame.sha256)}`]));

  const attackGroup = node("section", "terminal-group");
  attackGroup.appendChild(node("h4", "", "Adversarial probes"));
  const cloud = node("div", "check-cloud");
  Object.entries(result.handshake.attacks || {}).forEach(([name, passed]) => {
    cloud.appendChild(node("span", `check-pill ${passed ? "" : "fail"}`, humanize(name)));
  });
  attackGroup.appendChild(cloud);
  target.appendChild(attackGroup);

  const primitiveGroup = node("section", "terminal-group");
  primitiveGroup.appendChild(node("h4", "", "Native engine checks"));
  const primitives = node("div", "check-cloud");
  result.checks.forEach((check) => primitives.appendChild(node("span", `check-pill ${check.passed ? "" : "fail"}`, check.label)));
  primitiveGroup.appendChild(primitives);
  target.appendChild(primitiveGroup);
}

function addTerminalGroup(target, title, rows) {
  const group = node("section", "terminal-group");
  group.appendChild(node("h4", "", title));
  rows.forEach(([label, value]) => {
    const row = node("div", "terminal-row");
    row.append(node("span", "", label), node("code", "", value ?? "unavailable"));
    group.appendChild(row);
  });
  target.appendChild(group);
}

function shortHash(value) {
  if (!value) return "unavailable";
  return `${String(value).slice(0, 12)}…${String(value).slice(-8)}`;
}

function humanize(value) {
  return String(value).replaceAll("_", " ");
}

function formatInteger(value) {
  if (!Number.isFinite(Number(value))) return "—";
  return Math.round(Number(value)).toLocaleString();
}

function compactNumber(value) {
  if (!Number.isFinite(Number(value))) return "—";
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(Number(value));
}

let toastTimer = null;
function showToast(message, isError = false) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 4200);
}

function openAccessDialog(message = "") {
  const dialog = byId("access-dialog");
  byId("access-error").textContent = message;
  if (!dialog.open) dialog.showModal();
  byId("access-token").focus();
}

async function saveAccessToken() {
  const token = byId("access-token").value.trim();
  if (!token) {
    byId("access-error").textContent = "Enter the token configured by the server operator.";
    return;
  }
  appState.bearerToken = token;
  sessionStorage.setItem("cr01_showcase_bearer", token);
  byId("access-error").textContent = "Checking token…";
  try {
    await connect();
    byId("access-dialog").close();
    byId("access-token").value = "";
    showToast("Controlled evidence access unlocked.");
  } catch (error) {
    appState.bearerToken = "";
    sessionStorage.removeItem("cr01_showcase_bearer");
    byId("access-error").textContent = error.message || "Token rejected.";
  }
}

async function exportEvidence(event) {
  event.preventDefault();
  try {
    const data = await apiFetch("/api/v1/evidence/export");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "cr01-evidence-snapshot.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Evidence snapshot exported.");
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) openAccessDialog();
    showToast(error.message || "Evidence export failed.", true);
  }
}

function installScrollSpy() {
  const links = [...document.querySelectorAll(".rail-nav a")];
  const targets = links.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    links.forEach((link) => link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`));
  }, { rootMargin: "-25% 0px -60%", threshold: [0, 0.15, 0.5] });
  targets.forEach((target) => observer.observe(target));
}

function wireEvents() {
  byId("run-proof").addEventListener("click", runProof);
  byId("access-button").addEventListener("click", () => openAccessDialog());
  byId("close-access").addEventListener("click", () => byId("access-dialog").close());
  byId("save-access").addEventListener("click", saveAccessToken);
  byId("access-token").addEventListener("keydown", (event) => {
    if (event.key === "Enter") saveAccessToken();
  });
  byId("export-link").addEventListener("click", exportEvidence);
  installScrollSpy();
}

async function boot() {
  wireEvents();
  try {
    await connect();
  } catch (error) {
    document.body.dataset.ready = "false";
    byId("rail-status").textContent = "Access required";
    if (error instanceof ApiError && error.status === 401) {
      byId("access-button").classList.remove("hidden");
      openAccessDialog("This evaluation surface requires an access token.");
    } else {
      showToast(error.message || "Could not load the evidence snapshot.", true);
    }
  }
}

boot();
