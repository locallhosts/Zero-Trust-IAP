// Types mirroring the Go structs served by the admin API.

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
  risk_score?: number;
  risk_action?: string;
  risk_reasons?: string[];
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

export interface SecurityReplayRequest {
  subject: string;
  authenticated: boolean;
  posture_ok: boolean;
  certificate_valid: boolean;
  policy_allowed: boolean;
  auth_method: "mtls" | "jwt" | "none";
  sensitive_resource: boolean;
  recent_denials: number;
}

export interface RiskResult {
  score: number;
  decision: "ALLOW" | "STEP_UP" | "DENY" | "QUARANTINE";
  reasons: string[];
}

export interface SecurityReplayResponse {
  input: SecurityReplayRequest;
  result: RiskResult;
}

export interface ApiError {
  error: string;
}
