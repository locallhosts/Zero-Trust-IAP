import type {
  Policy,
  AccessLogEntry,
  RotationStatus,
  ApiError,
  SecurityReplayRequest,
  SecurityReplayResponse,
} from "./types.js";

const TOKEN_STORAGE_KEY = "iap_admin_token";

export function getStoredToken(): string {
  return localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
}

export function setStoredToken(token: string): void {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

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

  async replaySecurity(request: SecurityReplayRequest): Promise<SecurityReplayResponse> {
    const res = await fetch(`${this.base}/api/security/replay`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(request),
    });
    return this.handle<SecurityReplayResponse>(res);
  }

  async rotationStatus(): Promise<RotationStatus> {
    const res = await fetch(`${this.base}/api/rotation/status`, { headers: this.headers() });
    return this.handle<RotationStatus>(res);
  }
}

export const api = new ApiClient();
