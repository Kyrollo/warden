export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
export type FirewallAction = 'BLOCK' | 'REDACT' | 'FLAG' | 'ALLOW';

export interface PiiEntity {
  entity_type: string;
  raw_value: string;
  masked_value: string;
  start: number;
  end: number;
}

export interface InspectionFinding {
  rule_id: string;
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  message: string;
  matched_text?: string | null;
}

export interface InspectionResult {
  request_id: string;
  timestamp: string;
  input_text: string;
  sanitized_text: string;
  action: FirewallAction;
  threat_severity: ThreatSeverity;
  threat_score: number;
  findings: InspectionFinding[];
  pii_entities: PiiEntity[];
  stage_latencies: Record<string, number>;
  total_latency_ms: number;
  blocked: boolean;
  block_reason?: string | null;
}

export interface FirewallPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  injection_sensitivity: number;
  jailbreak_threshold: number;
  pii_masking_enabled: boolean;
  pii_types: string[];
  canary_token: string;
  action_on_critical: FirewallAction;
  action_on_high: FirewallAction;
  action_on_pii: FirewallAction;
  fail_mode: string;
}

export interface AuditIncident {
  audit_id: string;
  timestamp: string;
  client_ip: string;
  request_id: string;
  prompt_preview: string;
  action: FirewallAction;
  threat_severity: ThreatSeverity;
  blocked_reason: string;
  resolution: string;
  stage_latencies: Record<string, number>;
}

export interface TrafficStreamItem {
  request_id: string;
  timestamp: string;
  source_ip: string;
  input_prompt_preview: string;
  threat_severity: ThreatSeverity;
  action: FirewallAction;
  resolution: string;
  latencies: Record<string, number>;
}

export interface RedTeamPreset {
  id: string;
  name: string;
  category: string;
  prompt: string;
  expected_severity: ThreatSeverity;
  expected_action: FirewallAction;
  description: string;
}

export interface RedTeamAttackResponse {
  prompt: string;
  sanitized_text: string;
  action: string;
  threat_severity: ThreatSeverity;
  threat_score: number;
  blocked: boolean;
  block_reason?: string | null;
  findings: InspectionFinding[];
  pii_entities: PiiEntity[];
  stage_latencies: Record<string, number>;
  total_latency_ms: number;
}
