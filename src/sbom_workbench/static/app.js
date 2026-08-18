"use strict";

const state = {
  token: null,
  csrf: null,
  modelEnabled: false,
  selectedRun: null,
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

async function api(path, options = {}) {
  if (!state.token) throw new Error("缺少本地会话令牌，请使用启动命令显示的专用链接。 ");
  const target = new URL(path, window.location.origin);
  if (target.origin !== window.location.origin) throw new Error("已阻止跨源请求");
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${state.token}`);
  if (options.method === "POST") {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", state.csrf || "");
  }
  const response = await fetch(target, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  const payload = await response.json().catch(() => ({ message: "服务返回了非 JSON 响应" }));
  if (!response.ok) throw new Error(payload.message || `请求失败：${response.status}`);
  return payload;
}

function setStatus(element, value) {
  const normalized = textValue(value).toUpperCase();
  element.textContent = normalized;
  element.className = "status status-neutral";
  if (normalized.includes("PASS") || normalized.includes("VALID") || normalized.includes("CLOSED")) {
    element.className = "status status-ok";
  } else if (normalized.includes("BLOCK") || normalized.includes("FAIL") || normalized.includes("REJECT")) {
    element.className = "status status-blocked";
  } else if (normalized.includes("OPEN") || normalized.includes("UNKNOWN") || normalized.includes("NOT_")) {
    element.className = "status status-warn";
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
      body: JSON.stringify({ conflict_id: conflictId }),
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
    button.addEventListener("click", () => {
      requestModelAdvice(runId, textValue(conflict.conflict_id), output, button);
    });
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

async function start() {
  captureSessionToken();
  if (!state.token) {
    setStatus(byId("session-state"), "SESSION_REQUIRED");
    byId("run-list").append(node("div", "error-card", "请使用服务启动时生成的本地专用链接。"));
    return;
  }
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf_token;
    state.modelEnabled = Boolean(session.model?.enabled);
    setStatus(byId("session-state"), "LOCAL_SESSION_ACTIVE");
    setStatus(byId("model-state"), state.modelEnabled ? "SHADOW_ONLY" : "MODEL_DISABLED");
    const runs = await api("/api/runs");
    renderRuns(runs.runs || []);
  } catch (error) {
    setStatus(byId("session-state"), "BLOCKED");
    byId("run-list").append(node("div", "error-card", `BLOCKED: ${error.message}`));
  }
}

start();
