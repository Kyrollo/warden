import {
  AuditIncident,
  FirewallPolicy,
  InspectionResult,
  RedTeamAttackResponse,
  RedTeamPreset,
  TrafficStreamItem,
} from '../types/warden';

const API_BASE = '/api/v1';

export async function fetchPolicies(): Promise<FirewallPolicy[]> {
  const res = await fetch(`${API_BASE}/policies`);
  if (!res.ok) throw new Error(`Failed to fetch policies: ${res.statusText}`);
  return res.json();
}

export async function updatePolicy(
  id: string,
  payload: Partial<FirewallPolicy>
): Promise<FirewallPolicy> {
  const res = await fetch(`${API_BASE}/policies/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Failed to update policy: ${res.statusText}`);
  return res.json();
}

export async function fetchIncidents(): Promise<AuditIncident[]> {
  const res = await fetch(`${API_BASE}/incidents`);
  if (!res.ok) throw new Error(`Failed to fetch incidents: ${res.statusText}`);
  return res.json();
}

export async function fetchTrafficStream(): Promise<TrafficStreamItem[]> {
  const res = await fetch(`${API_BASE}/incidents/traffic`);
  if (!res.ok) throw new Error(`Failed to fetch traffic stream: ${res.statusText}`);
  return res.json();
}

export async function fetchPresets(): Promise<RedTeamPreset[]> {
  const res = await fetch(`${API_BASE}/lab/presets`);
  if (!res.ok) throw new Error(`Failed to fetch presets: ${res.statusText}`);
  return res.json();
}

export async function runRedTeamAttack(
  prompt: string,
  policyId: string = 'policy_genai_enterprise'
): Promise<RedTeamAttackResponse> {
  const res = await fetch(`${API_BASE}/lab/attack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, policy_id: policyId }),
  });
  if (!res.ok) throw new Error(`Attack test failed: ${res.statusText}`);
  return res.json();
}

export async function inspectPrompt(
  prompt: string,
  policyId: string = 'policy_genai_enterprise'
): Promise<InspectionResult> {
  const res = await fetch(`${API_BASE}/inspect/input`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, policy_id: policyId }),
  });
  if (!res.ok) throw new Error(`Inspection failed: ${res.statusText}`);
  return res.json();
}
