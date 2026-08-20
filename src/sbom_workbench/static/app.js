"use strict";

const state = {
  token: null,
  csrf: null,
  modelEnabled: false,
  scannerEnabled: false,
  scanner: null,
  selectedRun: null,
  selectedFiles: [],
  sourceKind: null,
  jobId: null,
  job: null,
  busy: false,
  pollTimer: null,
};

const byId = (id) => document.getElementById(id);

function textValue(value) {
  if (value === null || value === undefined) return "UNKNOWN";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value, null, 2);
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function captureSessionToken() {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const token = parameters.get("token");
  if (token) {
    window.sessionStorage.setItem("sbom_session_token", token);
    window.history.replaceState(null, "", window.location.pathname);
  }
  state.token = window.sessionStorage.getItem("sbom_session_token");
}

class ApiError extends Error {
  constructor(message, code = "REQUEST_FAILED", status = 0) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function authenticatedHeaders(extra = {}) {
  const headers = new Headers(extra);
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${state.token}`);
  return headers;
}

async function api(path, options = {}) {
  if (!state.token) throw new ApiError("缺少本地会话令牌，请使用服务启动时显示的专用链接。", "SESSION_REQUIRED");
  const target = new URL(path, window.location.origin);
  if (target.origin !== window.location.origin) throw new ApiError("已阻止跨源请求", "ORIGIN_BLOCKED");
  const method = (options.method || "GET").toUpperCase();
  const headers = authenticatedHeaders(options.headers || {});
  let body = options.body;
  if (!["GET", "HEAD"].includes(method)) {
    headers.set("X-CSRF-Token", state.csrf || "");
  }
  if (body !== undefined && !(body instanceof Blob) && !(body instanceof File)) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }
  const response = await fetch(target, {
    ...options,
    method,
    body,
    headers,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  const payload = await response.json().catch(() => ({ message: "服务返回了非 JSON 响应" }));
  if (!response.ok) {
    throw new ApiError(payload.message || `请求失败：${response.status}`, payload.error, response.status);
  }
  return payload;
}

async function uploadFile(path, file) {
  const target = new URL(path, window.location.origin);
  const headers = authenticatedHeaders({ "Content-Type": "application/octet-stream" });
  headers.set("X-CSRF-Token", state.csrf || "");
  const response = await fetch(target, {
    method: "PUT",
    headers,
    body: file,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  const payload = await response.json().catch(() => ({ message: "上传响应不是 JSON" }));
  if (!response.ok) throw new ApiError(payload.message || "文件上传失败", payload.error, response.status);
  return payload;
}

function setStatus(element, value) {
  const normalized = textValue(value).toUpperCase();
  element.textContent = normalized;
  element.className = "status status-neutral";
  if (
    normalized.includes("BLOCK")
    || normalized.includes("FAIL")
    || normalized.includes("REJECT")
    || normalized.includes("DISABLED")
    || normalized.includes("NOT_CONFIGURED")
  ) {
    element.className = "status status-blocked";
  } else if (
    normalized.includes("HOLD")
    || normalized.includes("OPEN")
    || normalized.includes("UNKNOWN")
    || normalized.includes("NOT_")
    || normalized.includes("WAIT")
  ) {
    element.className = "status status-warn";
  } else if (
    normalized.includes("PASS")
    || normalized.includes("VALID")
    || normalized.includes("COMPLETE")
    || normalized.includes("ACTIVE")
    || normalized.includes("ENABLED")
  ) {
    element.className = "status status-ok";
  } else if (
    normalized.includes("QUEUE")
  ) {
    element.className = "status status-warn";
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "UNKNOWN";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes;
  let index = -1;
  do {
    value /= 1024;
    index += 1;
  } while (value >= 1024 && index < units.length - 1);
  return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[index]}`;
}

function shortHash(value) {
  const text = textValue(value);
  return /^[0-9a-f]{64}$/.test(text) ? `${text.slice(0, 12)}…${text.slice(-8)}` : text;
}

function showView(name, focus = false) {
  const generate = name === "generate";
  byId("generate-view").classList.toggle("hidden", !generate);
  byId("evidence-view").classList.toggle("hidden", generate);
  const generateTab = byId("generate-tab");
  const evidenceTab = byId("evidence-tab");
  generateTab.classList.toggle("active", generate);
  evidenceTab.classList.toggle("active", !generate);
  generateTab.setAttribute("aria-selected", String(generate));
  evidenceTab.setAttribute("aria-selected", String(!generate));
  generateTab.tabIndex = generate ? 0 : -1;
  evidenceTab.tabIndex = generate ? -1 : 0;
  if (focus) (generate ? generateTab : evidenceTab).focus();
}

function bindTabs() {
  const tabs = [byId("generate-tab"), byId("evidence-tab")];
  tabs[0].addEventListener("click", () => showView("generate"));
  tabs[1].addEventListener("click", () => showView("evidence"));
  for (const tab of tabs) {
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" || event.key === "ArrowLeft" ? 0 : 1;
      showView(next === 0 ? "generate" : "evidence", true);
    });
  }
}

function workflowStep(number) {
  for (const item of document.querySelectorAll(".workflow-steps li")) {
    const itemStep = Number(item.dataset.step);
    item.classList.toggle("current", itemStep === number);
    item.classList.toggle("complete", itemStep < number);
  }
}

function processState(activeName, percent, detail, blocked = false) {
  const names = ["prepare", "upload", "scan", "verify"];
  const activeIndex = names.indexOf(activeName);
  for (const item of byId("process-list").querySelectorAll("li")) {
    const index = names.indexOf(item.dataset.process);
    item.classList.toggle("active", index === activeIndex && !blocked);
    item.classList.toggle("complete", activeIndex >= 0 && index < activeIndex);
    item.classList.toggle("blocked", index === activeIndex && blocked);
  }
  const bounded = Math.max(0, Math.min(100, Math.round(percent)));
  byId("process-percent").textContent = `${bounded}%`;
  byId("progress-fill").style.width = `${bounded}%`;
  byId("process-detail").textContent = detail;
}

function resetProcess() {
  workflowStep(1);
  processState(null, 0, "选择范围后即可开始。");
  byId("process-title").textContent = "等待源码选择";
  byId("scan-error-panel").classList.add("hidden");
  byId("scan-result").classList.add("hidden");
}

function limits() {
  return state.scanner?.limits || {
    max_files: 10000,
    max_total_bytes: 1024 * 1024 * 1024,
    max_single_file_bytes: 256 * 1024 * 1024,
    max_depth: 64,
  };
}

function sourcePath(file, kind) {
  return kind === "directory" ? file.webkitRelativePath : file.name;
}

function selectionError(message) {
  const target = byId("source-error");
  target.textContent = message;
  target.classList.toggle("hidden", !message);
}

function validateFiles(files, kind) {
  const currentLimits = limits();
  if (!files.length) throw new Error("没有读取到所选文件，请重新选择。 ");
  if (files.length > currentLimits.max_files) {
    throw new Error(`所选文件为 ${files.length} 个，超过 ${currentLimits.max_files} 个的界面预算。`);
  }
  const paths = new Set();
  let total = 0;
  for (const file of files) {
    const path = sourcePath(file, kind);
    if (!path || path !== path.normalize("NFC")) {
      throw new Error("至少一个文件名不是 Unicode NFC；请规范化文件名后重试。 ");
    }
    if (path.includes("\\") || path.startsWith("/") || path.split("/").some((part) => ["", ".", ".."].includes(part))) {
      throw new Error(`文件路径“${path}”不是安全的相对路径。`);
    }
    if (paths.has(path)) throw new Error(`文件路径“${path}”重复。`);
    paths.add(path);
    if (file.size > currentLimits.max_single_file_bytes) {
      throw new Error(`文件“${path}”为 ${formatBytes(file.size)}，超过单文件预算。`);
    }
    total += file.size;
    if (total > currentLimits.max_total_bytes) throw new Error("所选文件总量超过 1 GiB 界面预算。 ");
  }
  if (total <= 0) throw new Error("所选文件不包含可扫描字节。 ");
  return total;
}

function updateStartButton() {
  const name = byId("product-name").value;
  const version = byId("declared-version").value;
  byId("start-scan").disabled = !(
    state.scannerEnabled
    && state.selectedFiles.length
    && name.trim()
    && version.trim()
    && !state.busy
  );
}

function acceptSelection(fileList, kind) {
  selectionError("");
  try {
    const files = Array.from(fileList);
    const total = validateFiles(files, kind);
    state.selectedFiles = files;
    state.sourceKind = kind;
    const paths = files.map((file) => sourcePath(file, kind));
    const top = kind === "directory" ? paths[0].split("/")[0] : `${files.length} 个文件`;
    byId("selection-name").textContent = top;
    byId("selection-stats").textContent = `${files.length} 个文件 · ${formatBytes(total)} · 本机字节快照`;
    byId("selection-summary").classList.remove("hidden");
    byId("source-picker").classList.add("hidden");
    byId("process-title").textContent = "已选择源码范围";
    processState("prepare", 4, "补充项目身份后即可创建受限导入任务。");
  } catch (error) {
    state.selectedFiles = [];
    state.sourceKind = null;
    selectionError(error.message);
  }
  updateStartButton();
}

function clearSelection() {
  state.selectedFiles = [];
  state.sourceKind = null;
  byId("files-input").value = "";
  byId("folder-input").value = "";
  byId("selection-summary").classList.add("hidden");
  byId("source-picker").classList.remove("hidden");
  selectionError("");
  if (!state.busy) resetProcess();
  updateStartButton();
}

function validateDeclaration(input, label) {
  const value = input.value;
  const valid = value.length >= 1
    && value.length <= 128
    && value === value.trim()
    && !Array.from(value).some((character) => character.codePointAt(0) < 0x20);
  input.setAttribute("aria-invalid", String(!valid));
  if (!valid) throw new Error(`${label}需为 1–128 个可见字符，且首尾不能有空格。`);
  return value;
}

function selectedFormat() {
  return document.querySelector('input[name="output_format"]:checked').value;
}

function setBusy(value) {
  state.busy = value;
  for (const element of [
    byId("choose-files"),
    byId("choose-folder"),
    byId("clear-selection"),
    byId("product-name"),
    byId("declared-version"),
  ]) element.disabled = value;
  for (const radio of document.querySelectorAll('input[name="output_format"]')) radio.disabled = value;
  updateStartButton();
}

function intakeManifest(productName, declaredVersion) {
  return {
    source_kind: state.sourceKind,
    product_name: productName,
    declared_version: declaredVersion,
    output_format: selectedFormat(),
    files: state.selectedFiles.map((file) => ({
      relative_path: sourcePath(file, state.sourceKind),
      size: file.size,
    })),
  };
}

async function uploadSelection() {
  let cursor = 0;
  let completed = 0;
  const count = state.selectedFiles.length;
  const worker = async () => {
    while (cursor < count) {
      const index = cursor;
      cursor += 1;
      await uploadFile(`/api/intakes/${state.jobId}/files/${index}`, state.selectedFiles[index]);
      completed += 1;
      const percent = 12 + (completed / count) * 40;
      processState("upload", percent, `已复制 ${completed} / ${count} 个文件到本机会话临时区。`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(3, count) }, () => worker()));
}

function renderBlocked(job, fallback) {
  setBusy(false);
  workflowStep(3);
  processState("scan", 64, "安全门已停止任务；没有生成可下载候选。", true);
  byId("process-title").textContent = "任务被安全门阻止";
  const message = job?.error?.message || fallback || "扫描未完成，请检查选择范围和本地运行时。";
  byId("scan-error-message").textContent = message;
  byId("scan-error-panel").classList.remove("hidden");
  byId("scan-result").classList.add("hidden");
}

function downloadOrder(downloads, requested) {
  const formats = Object.keys(downloads || {});
  return formats.sort((left, right) => {
    if (left === requested) return -1;
    if (right === requested) return 1;
    if (left === "scan-receipt") return 1;
    if (right === "scan-receipt") return -1;
    return left.localeCompare(right);
  });
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer), (value) => value.toString(16).padStart(2, "0")).join("");
}

async function downloadArtifact(formatId, metadata, button) {
  const previous = button.querySelector("span:last-child").textContent;
  button.disabled = true;
  button.querySelector("span:last-child").textContent = "准备中";
  try {
    const target = new URL(metadata.url, window.location.origin);
    const response = await fetch(target, {
      headers: authenticatedHeaders(),
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({ message: `下载失败：${response.status}` }));
      throw new Error(payload.message);
    }
    const bytes = await response.arrayBuffer();
    const digest = hex(await window.crypto.subtle.digest("SHA-256", bytes));
    if (digest !== metadata.sha256 || response.headers.get("X-Content-SHA256") !== metadata.sha256) {
      throw new Error("下载字节与候选 SHA-256 不一致，已阻止保存。 ");
    }
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = metadata.filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    button.querySelector("span:last-child").textContent = "已验证";
    window.setTimeout(() => {
      button.querySelector("span:last-child").textContent = previous;
      button.disabled = false;
    }, 1200);
  } catch (error) {
    button.querySelector("span:last-child").textContent = "失败";
    byId("process-detail").textContent = `下载被阻止：${error.message}`;
    button.disabled = false;
  }
}

function renderResult(job) {
  setBusy(false);
  state.job = job;
  workflowStep(4);
  processState("verify", 100, "扫描输出与源码 exact-set 已复验；下载候选已去除已知本机会话路径。 ");
  for (const item of byId("process-list").querySelectorAll("li")) {
    item.classList.remove("active");
    item.classList.add("complete");
  }
  byId("process-title").textContent = "候选验证完成";
  byId("scan-error-panel").classList.add("hidden");
  byId("scan-result").classList.remove("hidden");
  const result = job.result || {};
  const coverageHold = textValue(result.coverage_gate).includes("HOLD")
    || textValue(result.component_population_gate).includes("HOLD");
  setStatus(
    byId("result-status"),
    coverageHold ? "VALID_WITH_COVERAGE_HOLD" : "INTEGRITY_VALID",
  );
  byId("result-components").textContent = textValue(result.component_count);
  byId("result-coverage").textContent = textValue(result.coverage_gate);
  byId("result-population").textContent = textValue(result.component_population_gate);
  byId("result-source-hash").textContent = shortHash(result.source_exact_set_sha256);
  byId("result-completion-hash").textContent = shortHash(result.completion_sha256);
  const list = byId("download-list");
  list.replaceChildren();
  for (const formatId of downloadOrder(result.downloads, job.requested_format)) {
    const metadata = result.downloads[formatId];
    const button = node("button", "download-button");
    button.type = "button";
    const copy = node("span");
    copy.append(
      node("strong", null, metadata.label + (formatId === job.requested_format ? " · 默认" : "")),
      node("small", null, `${metadata.filename}\n${formatBytes(metadata.size)} · SHA-256 ${shortHash(metadata.sha256)}`),
    );
    button.append(copy, node("span", null, "下载"));
    button.addEventListener("click", () => downloadArtifact(formatId, metadata, button));
    list.append(button);
  }
}

async function pollJob() {
  try {
    const job = await api(`/api/intakes/${state.jobId}`);
    state.job = job;
    if (job.status === "COMPLETE") {
      state.pollTimer = null;
      renderResult(job);
      return;
    }
    if (job.status === "BLOCKED") {
      state.pollTimer = null;
      renderBlocked(job);
      return;
    }
    if (job.status === "QUEUED") {
      processState("scan", 58, "任务已进入本地单工作线程队列。 ");
    } else {
      processState("scan", 64, "Syft 正在断网沙箱中扫描；大型项目通常需要数分钟。 ");
    }
    state.pollTimer = window.setTimeout(pollJob, 850);
  } catch (error) {
    state.pollTimer = null;
    renderBlocked(null, error.message);
  }
}

async function startScan(event) {
  event.preventDefault();
  if (state.busy || !state.scannerEnabled) return;
  byId("scan-error-panel").classList.add("hidden");
  byId("scan-result").classList.add("hidden");
  try {
    const productName = validateDeclaration(byId("product-name"), "项目或产品名称");
    const declaredVersion = validateDeclaration(byId("declared-version"), "版本或快照标签");
    validateFiles(state.selectedFiles, state.sourceKind);
    setBusy(true);
    workflowStep(2);
    byId("process-title").textContent = "正在创建受限导入";
    processState("prepare", 8, "服务正在冻结相对路径、文件数和字节预算。 ");
    const created = await api("/api/intakes", {
      method: "POST",
      body: intakeManifest(productName, declaredVersion),
    });
    state.jobId = created.job_id;
    processState("upload", 12, `开始复制 ${state.selectedFiles.length} 个所选文件。`);
    await uploadSelection();
    workflowStep(3);
    processState("scan", 54, "所选字节已完整写入本机会话临时区，正在启动断网扫描。 ");
    await api(`/api/intakes/${state.jobId}/complete`, { method: "POST", body: {} });
    processState("scan", 58, "扫描器将重新验证运行时哈希、版本、回执和断网策略。 ");
    await pollJob();
  } catch (error) {
    renderBlocked(null, error.message);
  }
}

async function discardCurrentJob() {
  if (!state.jobId) return;
  const button = byId("discard-job");
  button.disabled = true;
  try {
    await api(`/api/intakes/${state.jobId}`, { method: "DELETE" });
    state.jobId = null;
    state.job = null;
    clearSelection();
    resetProcess();
  } catch (error) {
    byId("process-detail").textContent = `临时数据未清除：${error.message}`;
  } finally {
    button.disabled = false;
  }
}

async function retryScan() {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  state.pollTimer = null;
  if (state.jobId) {
    try {
      await api(`/api/intakes/${state.jobId}`, { method: "DELETE" });
    } catch (error) {
      byId("scan-error-message").textContent = `旧任务未能清除：${error.message}`;
      return;
    }
  }
  state.jobId = null;
  state.job = null;
  setBusy(false);
  byId("scan-error-panel").classList.add("hidden");
  workflowStep(1);
  processState("prepare", 4, "已保留浏览器中的选择；检查字段后可重新生成。 ");
}

function bindGenerator() {
  byId("choose-files").addEventListener("click", () => byId("files-input").click());
  byId("choose-folder").addEventListener("click", () => byId("folder-input").click());
  byId("files-input").addEventListener("change", (event) => acceptSelection(event.target.files, "files"));
  byId("folder-input").addEventListener("change", (event) => acceptSelection(event.target.files, "directory"));
  byId("clear-selection").addEventListener("click", clearSelection);
  byId("scan-form").addEventListener("submit", startScan);
  byId("retry-scan").addEventListener("click", retryScan);
  byId("discard-job").addEventListener("click", discardCurrentJob);
  for (const input of [byId("product-name"), byId("declared-version")]) {
    input.addEventListener("input", updateStartButton);
    input.addEventListener("blur", () => {
      if (!input.value) return;
      try {
        validateDeclaration(input, input === byId("product-name") ? "项目或产品名称" : "版本或快照标签");
      } catch (error) {
        byId("process-detail").textContent = error.message;
      }
    });
  }
}

function renderDetails(container, value, excluded = new Set()) {
  container.replaceChildren();
  const entries = Object.entries(value || {})
    .filter(([key]) => !excluded.has(key))
    .sort(([left], [right]) => left.localeCompare(right));
  for (const [key, item] of entries) {
    const wrapper = node("div");
    wrapper.append(node("dt", null, key), node("dd", null, textValue(item)));
    container.append(wrapper);
  }
  if (!entries.length) {
    const wrapper = node("div");
    wrapper.append(node("dt", null, "status"), node("dd", null, "NOT_ASSESSED"));
    container.append(wrapper);
  }
}

function renderComponents(components) {
  const body = byId("components-body");
  body.replaceChildren();
  for (const component of components) {
    const row = node("tr");
    const name = component.name ?? component.component_name ?? component.component_id;
    const identifiers = component.identifiers ?? component.purl ?? component.identifier;
    const status = component.status ?? component.reconciliation_status ?? "UNKNOWN";
    for (const value of [name, component.version, component.producer ?? component.supplier, identifiers, status]) {
      row.append(node("td", null, textValue(value)));
    }
    body.append(row);
  }
  if (!components.length) {
    const row = node("tr");
    const cell = node("td", null, "没有已登记组件");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
  }
}

async function requestModelAdvice(runId, conflictId, output, button) {
  button.disabled = true;
  output.textContent = "正在请求本地 shadow 建议…";
  try {
    const result = await api(`/api/runs/${runId}/model-advice`, {
      method: "POST",
      body: { conflict_id: conflictId },
    });
    output.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    output.textContent = `BLOCKED: ${error.message}`;
  } finally {
    button.disabled = !state.modelEnabled;
  }
}

function renderConflicts(runId, reconciliation) {
  const list = byId("conflict-list");
  list.replaceChildren();
  const conflicts = Array.isArray(reconciliation.conflicts) ? reconciliation.conflicts : [];
  for (const conflict of conflicts) {
    const card = node("article", "conflict-card");
    const top = node("div", "conflict-top");
    const title = node("h4", null, `${textValue(conflict.field)} · ${textValue(conflict.conflict_id)}`);
    const button = node("button", "model-button", state.modelEnabled ? "获取 shadow 建议" : "模型已关闭");
    button.type = "button";
    button.disabled = !state.modelEnabled;
    const output = node("pre", "model-result", "尚未请求；模型结果不会自动写回事实或状态。 ");
    button.addEventListener("click", () => requestModelAdvice(runId, textValue(conflict.conflict_id), output, button));
    top.append(title, button);
    card.append(top, node("pre", null, JSON.stringify(conflict, null, 2)), output);
    list.append(card);
  }
  if (!conflicts.length) list.append(node("p", "muted", "没有已登记冲突。此显示不单独证明对账已闭合。"));
}

function renderDashboard(dashboard) {
  byId("empty-state").classList.add("hidden");
  byId("dashboard").classList.remove("hidden");
  byId("run-title").textContent = dashboard.run_id;
  byId("classification").textContent = dashboard.classification;
  byId("run-subtitle").textContent = `${textValue(dashboard.release.product)} · Build ${textValue(dashboard.release.build_id)}`;
  byId("component-count").textContent = String(dashboard.components.length);
  renderDetails(byId("release-grid"), dashboard.release);
  renderComponents(dashboard.components);
  const reconciliation = dashboard.reconciliation || {};
  setStatus(byId("reconciliation-status"), reconciliation.status ?? "UNKNOWN");
  renderDetails(byId("reconciliation-grid"), reconciliation, new Set(["conflicts"]));
  renderConflicts(dashboard.run_id, reconciliation);
  const validation = dashboard.validation || {};
  setStatus(byId("validation-status"), validation.status ?? "NOT_ASSESSED");
  renderDetails(byId("validation-grid"), validation);
  byId("authority-boundary").textContent = dashboard.authority_boundary?.message
    || "没有制造商授权、CAB结论、CRA符合或认证权限。";
}

async function selectRun(runId, button) {
  for (const item of document.querySelectorAll(".run-button")) item.classList.remove("active");
  button.classList.add("active");
  state.selectedRun = runId;
  try {
    renderDashboard(await api(`/api/runs/${runId}`));
  } catch (error) {
    byId("dashboard").classList.add("hidden");
    const empty = byId("empty-state");
    empty.classList.remove("hidden");
    empty.replaceChildren(node("div", "error-card", `BLOCKED: ${error.message}`));
  }
}

function renderRuns(runs) {
  const list = byId("run-list");
  list.replaceChildren();
  byId("run-count").textContent = String(runs.length);
  for (const run of runs) {
    const button = node("button", "run-button");
    button.type = "button";
    button.append(
      node("span", "run-name", textValue(run.product)),
      node("span", "run-meta", `${textValue(run.run_id)}\n${textValue(run.classification)} · ${run.component_count} 组件`),
    );
    button.addEventListener("click", () => selectRun(run.run_id, button));
    list.append(button);
  }
  if (!runs.length) list.append(node("p", "muted", "当前没有已登记运行。"));
}

function configureScanner(scanner) {
  state.scanner = scanner || {};
  state.scannerEnabled = Boolean(scanner?.enabled);
  setStatus(byId("scanner-state"), state.scannerEnabled ? "SCANNER_ENABLED" : "SCANNER_NOT_CONFIGURED");
  const message = byId("scanner-message");
  message.classList.toggle("blocked", !state.scannerEnabled);
  message.textContent = state.scannerEnabled
    ? "Syft 1.50.0 已配置；每次扫描都会复验哈希、回执、版本与断网策略。"
    : "扫描器未配置。请运行 scripts/acquire_syft_m3a.sh 后重启服务。";
  const currentLimits = limits();
  byId("selection-limit").textContent = `${currentLimits.max_files.toLocaleString()} 文件 · ${formatBytes(currentLimits.max_total_bytes)}`;
  updateStartButton();
}

async function start() {
  bindTabs();
  bindGenerator();
  resetProcess();
  captureSessionToken();
  if (!state.token) {
    setStatus(byId("session-state"), "SESSION_REQUIRED");
    configureScanner(null);
    byId("run-list").append(node("div", "error-card", "请使用服务启动时生成的本地专用链接。"));
    return;
  }
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf_token;
    state.modelEnabled = Boolean(session.model?.enabled);
    setStatus(byId("session-state"), "LOCAL_SESSION_ACTIVE");
    setStatus(byId("model-state"), state.modelEnabled ? "SHADOW_ONLY" : "MODEL_DISABLED");
    if (!state.modelEnabled) byId("model-state").className = "status status-neutral";
    configureScanner(session.scanner);
    const runs = await api("/api/runs");
    renderRuns(runs.runs || []);
  } catch (error) {
    setStatus(byId("session-state"), "BLOCKED");
    configureScanner(null);
    byId("run-list").append(node("div", "error-card", `BLOCKED: ${error.message}`));
    byId("process-detail").textContent = `本地会话启动失败：${error.message}`;
  }
}

start();
