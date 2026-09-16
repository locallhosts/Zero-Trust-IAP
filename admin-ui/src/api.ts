import type { Policy, AccessLogEntry, RotationStatus, ApiError, SecurityReplayRequest, SecurityReplayResponse } from "./types.js";

const TOKEN_STORAGE_KEY = "iap_admin_token";

export function getStoredToken(): string { return localStorage.getItem(TOKEN_STORAGE_KEY) ?? ""; }
export function setStoredToken(token: string): void { localStorage.setItem(TOKEN_STORAGE_KEY, token); }

class ApiClient {
  private base = "";

  private headers(): HeadersInit {
    const token = getStoredToken();
    const h: HeadersInit = { "Content-Type": "application/json" };
    if (token) h["X-Admin-Token"] = token;
    return h;
  }

  private async handle<T>(res: Response): Promise<T> {
    if (!res.ok) {
      let message = `request failed with status ${res.status}`;
      try {
        const body = (await res.json()) as ApiError;
        if (body.error) message = body.error;
      } catch {}
      throw new Error(message);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  async listPolicies(): Promise<Policy[]> {
    const value = await this.handle<Policy[] | null>(await fetch(`${this.base}/api/policies`, { headers: this.headers() }));
    return Array.isArray(value) ? value : [];
  }

  async savePolicy(policy: Policy): Promise<Policy> {
    return this.handle(await fetch(`${this.base}/api/policies`, { method: "POST", headers: this.headers(), body: JSON.stringify(policy) }));
  }

  async deletePolicy(id: string): Promise<void> {
    return this.handle(await fetch(`${this.base}/api/policies/${encodeURIComponent(id)}`, { method: "DELETE", headers: this.headers() }));
  }

  async recentLogs(limit = 100): Promise<AccessLogEntry[]> {
    const value = await this.handle<AccessLogEntry[] | null>(await fetch(`${this.base}/api/logs?limit=${limit}`, { headers: this.headers() }));
    return Array.isArray(value) ? value : [];
  }

  async replaySecurity(request: SecurityReplayRequest): Promise<SecurityReplayResponse> {
    return this.handle(await fetch(`${this.base}/api/security/replay`, { method: "POST", headers: this.headers(), body: JSON.stringify(request) }));
  }

  async rotationStatus(): Promise<RotationStatus> {
    return this.handle(await fetch(`${this.base}/api/rotation/status`, { headers: this.headers() }));
  }

  async rotateNow(): Promise<RotationStatus> {
    return this.handle(await fetch(`${this.base}/api/rotation/rotate-now`, { method: "POST", headers: this.headers() }));
  }
}

export const api = new ApiClient();
