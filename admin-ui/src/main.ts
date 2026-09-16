import { api, getStoredToken, setStoredToken } from "./api.js";
import type { Policy, AccessLogEntry, RotationStatus } from "./types.js";

type Tab = "policies" | "logs" | "rotation";

let activeTab: Tab = "policies";
let pollHandle: number | undefined;

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function fmtTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

// ---------- Token bar ----------

function initTokenBar(): void {
  const input = $("admin-token-input") as HTMLInputElement;
  input.value = getStoredToken();
  $("admin-token-save").addEventListener("click", () => {
    setStoredToken(input.value.trim());
    refreshActiveTab();
  });
}

// ---------- Tabs ----------

function initTabs(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab as Tab;
      setActiveTab(tab);
    });
  });
}

function setActiveTab(tab: Tab): void {
  activeTab = tab;
  document.querySelectorAll<HTMLElement>(".tab-panel").forEach((p) => {
    p.classList.toggle("hidden", p.dataset.panel !== tab);
  });
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });
  refreshActiveTab();
}

function refreshActiveTab(): void {
  if (activeTab === "policies") void renderPolicies();
  else if (activeTab === "logs") void renderLogs();
  else if (activeTab === "rotation") void renderRotation();
}

// ---------- Policies ----------

function emptyPolicy(): Policy {
  return {
    id: "",
    describe: "",
    subjects: [],
    path_prefixes: [],
    methods: [],
    posture: {},
    enabled: true,
  };
}

let editingPolicy: Policy | null = null;

async function renderPolicies(): Promise<void> {
  const container = $("policies-list");
  container.innerHTML = `<p class="muted">Loading policies…</p>`;
  try {
    const policies = await api.listPolicies();
    if (policies.length === 0) {
      container.innerHTML = `<p class="muted">No policies defined yet. Add one below.</p>`;
      return;
    }
    container.innerHTML = policies
      .map((p) => policyCardHtml(p))
      .join("");
    container.querySelectorAll<HTMLButtonElement>("[data-edit]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = policies.find((x) => x.id === btn.dataset.edit);
        if (p) openEditor(p);
      });
    });
    container.querySelectorAll<HTMLButtonElement>("[data-delete]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm(`Delete policy "${btn.dataset.delete}"?`)) return;
        await api.deletePolicy(btn.dataset.delete!);
        void renderPolicies();
      });
    });
  } catch (err) {
    container.innerHTML = `<p class="error">Failed to load policies: ${escapeHtml((err as Error).message)}</p>`;
  }
}

function policyCardHtml(p: Policy): string {
  const posture: string[] = [];
  if (p.posture.require_disk_encryption) posture.push("disk encryption");
  if (p.posture.require_edr) posture.push("EDR");
  if (p.posture.min_patch_level) posture.push(`patch ≥ ${p.posture.min_patch_level}`);
  const postureStr = posture.length ? posture.join(", ") : "none";

  return `
    <div class="card ${p.enabled ? "" : "disabled"}">
      <div class="card-header">
        <span class="policy-id">${escapeHtml(p.id)}</span>
        <span class="badge ${p.enabled ? "badge-on" : "badge-off"}">${p.enabled ? "enabled" : "disabled"}</span>
      </div>
      <p class="describe">${escapeHtml(p.describe)}</p>
      <dl class="policy-meta">
        <dt>Subjects</dt><dd>${p.subjects.map(escapeHtml).join(", ") || "—"}</dd>
        <dt>Paths</dt><dd>${p.path_prefixes.map(escapeHtml).join(", ") || "—"}</dd>
        <dt>Methods</dt><dd>${(p.methods && p.methods.length ? p.methods.join(", ") : "any")}</dd>
        <dt>Posture</dt><dd>${escapeHtml(postureStr)}</dd>
      </dl>
      <div class="card-actions">
        <button data-edit="${escapeHtml(p.id)}">Edit</button>
        <button data-delete="${escapeHtml(p.id)}" class="danger">Delete</button>
      </div>
    </div>
  `;
}

function openEditor(p: Policy): void {
  editingPolicy = { ...p, posture: { ...p.posture } };
  fillEditorForm(editingPolicy);
  $("policy-editor").classList.remove("hidden");
}

function fillEditorForm(p: Policy): void {
  (document.getElementById("f-id") as HTMLInputElement).value = p.id;
  (document.getElementById("f-describe") as HTMLTextAreaElement).value = p.describe;
  (document.getElementById("f-subjects") as HTMLTextAreaElement).value = p.subjects.join("\n");
  (document.getElementById("f-paths") as HTMLTextAreaElement).value = p.path_prefixes.join("\n");
  (document.getElementById("f-methods") as HTMLInputElement).value = (p.methods ?? []).join(", ");
  (document.getElementById("f-enabled") as HTMLInputElement).checked = p.enabled;
  (document.getElementById("f-disk") as HTMLInputElement).checked = !!p.posture.require_disk_encryption;
  (document.getElementById("f-edr") as HTMLInputElement).checked = !!p.posture.require_edr;
  (document.getElementById("f-patch") as HTMLInputElement).value = p.posture.min_patch_level ?? "";
}

function readEditorForm(): Policy {
  const id = (document.getElementById("f-id") as HTMLInputElement).value.trim();
  const describe = (document.getElementById("f-describe") as HTMLTextAreaElement).value.trim();
  const subjects = (document.getElementById("f-subjects") as HTMLTextAreaElement).value
    .split("\n").map((s) => s.trim()).filter(Boolean);
  const path_prefixes = (document.getElementById("f-paths") as HTMLTextAreaElement).value
    .split("\n").map((s) => s.trim()).filter(Boolean);
  const methods = (document.getElementById("f-methods") as HTMLInputElement).value
    .split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
  const enabled = (document.getElementById("f-enabled") as HTMLInputElement).checked;
  const require_disk_encryption = (document.getElementById("f-disk") as HTMLInputElement).checked;
  const require_edr = (document.getElementById("f-edr") as HTMLInputElement).checked;
  const min_patch_level = (document.getElementById("f-patch") as HTMLInputElement).value.trim();

  return {
    id,
    describe,
    subjects,
    path_prefixes,
    methods,
    enabled,
    posture: { require_disk_encryption, require_edr, min_patch_level: min_patch_level || undefined },
  };
}

function initPolicyEditor(): void {
  $("new-policy-btn").addEventListener("click", () => openEditor(emptyPolicy()));
  $("editor-cancel").addEventListener("click", () => {
    $("policy-editor").classList.add("hidden");
    editingPolicy = null;
  });
  $("editor-save").addEventListener("click", async () => {
    const p = readEditorForm();
    if (!p.id) {
      alert("Policy ID is required.");
      return;
    }
    try {
      await api.savePolicy(p);
      $("policy-editor").classList.add("hidden");
      editingPolicy = null;
      void renderPolicies();
    } catch (err) {
      alert(`Failed to save policy: ${(err as Error).message}`);
    }
  });
}

// ---------- Access Logs ----------

async function renderLogs(): Promise<void> {
  const container = $("logs-table-body");
  try {
    const logs = await api.recentLogs(200);
    if (logs.length === 0) {
      container.innerHTML = `<tr><td colspan="7" class="muted">No access log entries yet.</td></tr>`;
      return;
    }
    container.innerHTML = logs.map((e) => logRowHtml(e)).join("");
  } catch (err) {
    container.innerHTML = `<tr><td colspan="7" class="error">Failed to load logs: ${escapeHtml((err as Error).message)}</td></tr>`;
  }
}

function logRowHtml(e: AccessLogEntry): string {
  return `
    <tr class="${e.allowed ? "row-allow" : "row-deny"}">
      <td>${fmtTime(e.timestamp)}</td>
      <td>${escapeHtml(e.subject || "—")}</td>
      <td>${escapeHtml(e.method)} ${escapeHtml(e.path)}</td>
      <td>${escapeHtml(e.auth_method)}</td>
      <td><span class="badge ${e.allowed ? "badge-on" : "badge-off"}">${e.allowed ? "ALLOW" : "DENY"}</span></td>
      <td>${escapeHtml(e.policy_id || "—")}</td>
      <td class="reason">${escapeHtml(e.reason)}</td>
    </tr>
  `;
}

// ---------- Rotation status ----------

async function renderRotation(): Promise<void> {
  const container = $("rotation-status");
  try {
    const status: RotationStatus = await api.rotationStatus();
    const healthy = status.source !== "disabled" && !status.last_error;
    container.innerHTML = `
      <div class="card ${healthy ? "" : "disabled"}">
        <div class="card-header">
          <span class="policy-id">Certificate Rotation</span>
          <span class="badge ${healthy ? "badge-on" : "badge-off"}">${status.source}</span>
        </div>
        <dl class="policy-meta">
          <dt>Last rotated</dt><dd>${fmtTime(status.last_rotated_at)}</dd>
          <dt>Expires</dt><dd>${fmtTime(status.not_after)}</dd>
          <dt>Serial</dt><dd>${escapeHtml(status.serial_number || "—")}</dd>
          ${status.last_error ? `<dt>Last error</dt><dd class="error">${escapeHtml(status.last_error)}</dd>` : ""}
        </dl>
        <p class="muted">Rotation runs automatically in the background (see internal/proxy/rotation.go). Certificates are re-issued from Vault's PKI engine once less than 20% of their TTL remains, and hot-swapped into the live TLS listener with zero downtime.</p>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<p class="error">Failed to load rotation status: ${escapeHtml((err as Error).message)}</p>`;
  }
}

// ---------- Boot ----------

function startPolling(): void {
  if (pollHandle) window.clearInterval(pollHandle);
  pollHandle = window.setInterval(() => refreshActiveTab(), 5000);
}

function main(): void {
  initTokenBar();
  initTabs();
  initPolicyEditor();
  setActiveTab("policies");
  startPolling();
}

document.addEventListener("DOMContentLoaded", main);
