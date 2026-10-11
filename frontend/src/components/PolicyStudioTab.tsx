import React, { useState } from 'react';
import { FirewallAction, FirewallPolicy } from '../types/warden';
import { updatePolicy } from '../lib/api';
import { Shield, Sliders, Key, Lock, CheckCircle2, Save, AlertTriangle } from 'lucide-react';

interface PolicyStudioTabProps {
  policy: FirewallPolicy | null;
  onPolicyUpdated: () => void;
}

export const PolicyStudioTab: React.FC<PolicyStudioTabProps> = ({ policy, onPolicyUpdated }) => {
  if (!policy) {
    return (
      <div className="flex h-64 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30 text-sm text-slate-400">
        Loading active firewall security policy...
      </div>
    );
  }

  const [sensitivity, setSensitivity] = useState<number>(policy.injection_sensitivity * 100);
  const [jailbreakThreshold, setJailbreakThreshold] = useState<number>(policy.jailbreak_threshold * 100);
  const [piiEnabled, setPiiEnabled] = useState<boolean>(policy.pii_masking_enabled);
  const [selectedPii, setSelectedPii] = useState<string[]>(policy.pii_types);
  const [actionCritical, setActionCritical] = useState<FirewallAction>(policy.action_on_critical);
  const [actionHigh, setActionHigh] = useState<FirewallAction>(policy.action_on_high);
  const [actionPii, setActionPii] = useState<FirewallAction>(policy.action_on_pii);
  const [saving, setSaving] = useState<boolean>(false);
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  const togglePiiType = (type: string) => {
    setSelectedPii((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  const handleSave = async () => {
    setSaving(true);
    setSavedSuccess(false);
    try {
      await updatePolicy(policy.id, {
        injection_sensitivity: sensitivity / 100,
        jailbreak_threshold: jailbreakThreshold / 100,
        pii_masking_enabled: piiEnabled,
        pii_types: selectedPii,
        action_on_critical: actionCritical,
        action_on_high: actionHigh,
        action_on_pii: actionPii,
      });
      setSavedSuccess(true);
      onPolicyUpdated();
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err: any) {
      alert(`Save error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const allPiiTypes = [
    { id: 'SSN', label: 'SSN (Social Security Number)' },
    { id: 'CREDIT_CARD', label: 'Credit Cards (Visa / MC / Amex)' },
    { id: 'EMAIL', label: 'Corporate Email Addresses' },
    { id: 'PHONE', label: 'Direct Phone Numbers' },
    { id: 'API_KEY', label: 'API Keys (OpenAI / GitHub / AWS)' },
    { id: 'MEDICAL_ID', label: 'Medical Record Numbers (MRN)' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-purple-950/80 p-2 text-purple-400 border border-purple-800/80">
            <Sliders className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Policy Rule Studio &amp; Threat Matrix</h3>
            <p className="text-xs text-slate-400">{policy.name} ({policy.id})</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {savedSuccess && (
            <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium">
              <CheckCircle2 className="h-4 w-4" /> Policy Saved
            </span>
          )}
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-xs font-semibold text-white shadow-md shadow-purple-900/40 hover:bg-purple-500 disabled:opacity-50 transition"
          >
            <Save className="h-3.5 w-3.5" />
            <span>{saving ? 'Saving...' : 'Deploy Policy Changes'}</span>
          </button>
        </div>
      </div>

      {/* Policy Rules Configuration Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Detection Sensitivity Sliders */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm space-y-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Threat Detection Sensitivities
          </h4>

          {/* Injection Sensitivity */}
          <div>
            <div className="flex items-center justify-between text-xs text-slate-200 mb-1">
              <span className="font-medium">Prompt Injection Sensitivity</span>
              <span className="font-mono font-bold text-purple-400">{sensitivity}%</span>
            </div>
            <input
              type="range"
              min="50"
              max="99"
              value={sensitivity}
              onChange={(e) => setSensitivity(parseInt(e.target.value))}
              className="w-full accent-purple-500"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Higher sensitivity blocks more aggressive indirect prompt boundaries.
            </p>
          </div>

          {/* Jailbreak Threshold */}
          <div>
            <div className="flex items-center justify-between text-xs text-slate-200 mb-1">
              <span className="font-medium">Zero-Shot Jailbreak Confidence Threshold</span>
              <span className="font-mono font-bold text-rose-400">{jailbreakThreshold}%</span>
            </div>
            <input
              type="range"
              min="60"
              max="99"
              value={jailbreakThreshold}
              onChange={(e) => setJailbreakThreshold(parseInt(e.target.value))}
              className="w-full accent-rose-500"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Confidence threshold required to neutralize persona overrides (DAN/Developer mode).
            </p>
          </div>

          {/* Canary Token Leak Detector Banner */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
                <Key className="h-3.5 w-3.5 text-cyan-400" />
                <span>Session Canary Secret Token</span>
              </div>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                MONITORED
              </span>
            </div>
            <p className="font-mono text-[11px] text-cyan-400 font-semibold">{policy.canary_token}</p>
            <p className="text-[10px] text-slate-500 mt-1">
              Injected into system instructions. If detected in user queries or output completions, firewall trips into 403 BLOCK.
            </p>
          </div>
        </div>

        {/* PII Masking & Action Selectors */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              PII &amp; Sensitive Entity Masking
            </h4>
            <button
              onClick={() => setPiiEnabled(!piiEnabled)}
              className={`text-xs px-2.5 py-0.5 rounded font-mono font-bold ${
                piiEnabled ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {piiEnabled ? 'MASKING ACTIVE' : 'DISABLED'}
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {allPiiTypes.map((pt) => {
              const active = selectedPii.includes(pt.id);
              return (
                <button
                  key={pt.id}
                  onClick={() => togglePiiType(pt.id)}
                  className={`flex items-center justify-between rounded-lg p-2.5 text-left text-xs border transition ${
                    active
                      ? 'border-cyan-500/50 bg-cyan-950/30 text-white font-medium'
                      : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/40'
                  }`}
                >
                  <span className="font-sans text-[11px]">{pt.label}</span>
                  <span className={`h-2.5 w-2.5 rounded-full ${active ? 'bg-cyan-400' : 'bg-slate-700'}`} />
                </button>
              );
            })}
          </div>

          {/* Action Policy Configuration */}
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Security Action Directives
            </h5>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="text-[10px] text-slate-500">Critical Threat Action</span>
                <div className="text-rose-400 font-bold">{actionCritical} (HTTP 403)</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <span className="text-[10px] text-slate-500">PII Entity Action</span>
                <div className="text-purple-400 font-bold">{actionPii} (IN-PLACE MASK)</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
