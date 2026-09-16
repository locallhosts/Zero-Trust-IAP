import type { Policy, AccessLogEntry, RotationStatus, ApiError } from "./types.js";

const TOKEN_STORAGE_KEY = "iap_admin_token";

export function getStoredToken(): string {
  return localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
}

export function setStoredToken(token: string): void {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

class ApiClient {
  // The admin UI is served by the same Go binary's admin listener, so
  // relative paths are correct both in local dev (served straight from
  // admin-ui/dist via `go run ./cmd/proxy`) and in any real deployment.
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
      } catch {
        /* body wasn't JSON; keep default message */
      }
      throw new Error(message);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  async listPolicies(): Promise<Policy[]> {
    const res = await fetch(`${this.base}/api/policies`, { headers: this.headers() });
    return this.handle<Policy[]>(res);
  }

  async savePolicy(policy: Policy): Promise<Policy> {
    const res = await fetch(`${this.base}/api/policies`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(policy),
    });
    return this.handle<Policy>(res);
  }

  async deletePolicy(id: string): Promise<void> {
    const res = await fetch(`${this.base}/api/policies/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    return this.handle<void>(res);
  }

  async recentLogs(limit = 100): Promise<AccessLogEntry[]> {
    const res = await fetch(`${this.base}/api/logs?limit=${limit}`, { headers: this.headers() });
    return this.handle<AccessLogEntry[]>(res);
  }

  async rotationStatus(): Promise<RotationStatus> {
    const res = await fetch(`${this.base}/api/rotation/status`, { headers: this.headers() });
    return this.handle<RotationStatus>(res);
  }
}

export const api = new ApiClient();
