// Types mirroring the Go structs served by internal/admin/api.go. Kept
// hand-in-sync with the backend rather than code-generated, since the
// surface is small and stable; see internal/policy/policy.go,
// internal/logging/access_log.go, and internal/proxy/rotation.go for the
// source of truth.

export interface PostureRequirement {
  require_disk_encryption?: boolean;
  require_edr?: boolean;
  min_patch_level?: string;
}

export interface Policy {
  id: string;
  describe: string;
  subjects: string[];
  path_prefixes: string[];
  methods?: string[];
  posture: PostureRequirement;
  enabled: boolean;
}

export interface AccessLogEntry {
  timestamp: string;
  subject: string;
  method: string;
  path: string;
  remote_addr: string;
  allowed: boolean;
  reason: string;
  policy_id?: string;
  auth_method: "mtls" | "jwt" | "none";
  spiffe_id?: string;
  latency_ms: number;
  status_code?: number;
}

export interface RotationStatus {
  last_rotated_at?: string;
  not_after?: string;
  serial_number?: string;
  last_error?: string;
  source: "vault" | "static-file" | "disabled";
}

export interface ApiError {
  error: string;
}
