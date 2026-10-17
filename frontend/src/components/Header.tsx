import React from 'react';
import { Shield, Cpu, Activity, Lock } from 'lucide-react';
import { FirewallPolicy } from '../types/warden';

interface HeaderProps {
  policy: FirewallPolicy | null;
}

export const Header: React.FC<HeaderProps> = ({ policy }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand & Project */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-purple-600 to-rose-700 flex items-center justify-center text-white font-bold shadow-lg shadow-purple-950/50">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white tracking-tight">Warden</span>
                <span className="rounded bg-purple-950/80 border border-purple-700/60 px-1.5 py-0.5 text-[10px] font-mono text-purple-300">
                  v1.0.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400">LLM Safety, Hallucination &amp; Prompt Injection Firewall</p>
            </div>
          </div>

          {/* Active Policy Pill */}
          <div className="hidden lg:flex items-center gap-2 border-l border-slate-800 pl-6 text-xs">
            <span className="text-slate-400">Policy:</span>
            <span className="font-semibold text-slate-200">{policy?.name || 'GenAI Enterprise Security'}</span>
            <span className="text-slate-600">|</span>
            <span className="text-purple-400 font-mono">Sens: {(policy ? policy.injection_sensitivity * 100 : 82).toFixed(0)}%</span>
            <span className="text-emerald-400 font-mono">PII: ACTIVE</span>
          </div>
        </div>

        {/* Right Status Badges */}
        <div className="flex items-center gap-4">
          {/* GPU Hardware Telemetry */}
          <div className="hidden sm:flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-xs">
            <Cpu className="h-3.5 w-3.5 text-purple-400" />
            <span className="text-slate-300 font-mono">Dedicated NVIDIA GPU (16GB)</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>

          {/* Firewall Status Pill */}
          <div className="flex items-center gap-1.5 rounded-lg border border-purple-800/60 bg-purple-950/40 px-3 py-1 text-xs font-mono font-semibold text-purple-300">
            <Lock className="h-3.5 w-3.5" />
            <span>FIREWALL: ARMED</span>
          </div>
        </div>
      </div>
    </header>
  );
};
