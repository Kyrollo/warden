import React from 'react';
import { AuditIncident, TrafficStreamItem } from '../types/warden';
import { PipelineDag } from './PipelineDag';
import { ShieldAlert, Activity, Globe2, Radio, AlertOctagon } from 'lucide-react';

interface SocOperationsTabProps {
  traffic: TrafficStreamItem[];
  incidents: AuditIncident[];
}

export const SocOperationsTab: React.FC<SocOperationsTabProps> = ({ traffic, incidents }) => {
  return (
    <div className="space-y-6">
      {/* Top Split: Live Stream (Left) & Pipeline DAG + Threat Map (Right) */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Real-Time Intercepted Prompt Traffic Stream */}
        <div className="lg:col-span-8 rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm">
          <div className="mb-3 flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-emerald-400 animate-pulse" />
              <div>
                <h3 className="text-sm font-bold text-white">
                  Real-Time Intercepted Prompt Traffic Stream
                </h3>
                <p className="text-xs text-slate-400">
                  Continuous edge inspection of enterprise LLM queries
                </p>
              </div>
            </div>
            <span className="flex items-center gap-1.5 rounded-full bg-emerald-950/80 border border-emerald-800/50 px-2.5 py-0.5 text-[11px] font-mono font-semibold text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" /> LIVE REFRESH
            </span>
          </div>

          <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-950/90 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px] backdrop-blur">
                <tr>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Input Prompt Preview</th>
                  <th className="py-2.5 px-3 text-center">Threat</th>
                  <th className="py-2.5 px-3 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {traffic.map((item, idx) => {
                  const isCrit = item.threat_severity === 'CRITICAL';
                  const isHigh = item.threat_severity === 'HIGH';
                  const isMed = item.threat_severity === 'MEDIUM';
                  const isSafe = item.threat_severity === 'SAFE';

                  return (
                    <tr key={idx} className="hover:bg-slate-800/30 transition">
                      <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                        {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '10:04:15'}
                      </td>
                      <td className="py-2 px-3 text-slate-300 whitespace-nowrap">{item.source_ip}</td>
                      <td className="py-2 px-3 text-slate-300 font-sans max-w-xs truncate">
                        {item.input_prompt_preview}
                      </td>
                      <td className="py-2 px-3 text-center">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                            isCrit
                              ? 'bg-rose-950 text-rose-300 border border-rose-800/80 shadow-sm shadow-rose-950'
                              : isHigh
                              ? 'bg-amber-950 text-amber-300 border border-amber-800/80'
                              : isMed
                              ? 'bg-purple-950 text-purple-300 border border-purple-800/80'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-800/80'
                          }`}
                        >
                          {item.threat_severity}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-center">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.resolution === 'REJECTED'
                              ? 'text-rose-400 bg-rose-950/60'
                              : item.resolution === 'REDACTED'
                              ? 'text-purple-400 bg-purple-950/60'
                              : 'text-emerald-400 bg-emerald-950/60'
                          }`}
                        >
                          {item.resolution}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Pane: Pipeline Latency DAG & Cyber Threat Map */}
        <div className="lg:col-span-4 space-y-4">
          <PipelineDag />

          {/* Incident Threat Map SVG */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Globe2 className="h-4 w-4 text-purple-400" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Global Threat Radar
                </h4>
              </div>
              <span className="text-[10px] font-mono text-rose-400 font-semibold">
                ACTIVE THREATS: 3
              </span>
            </div>

            <div className="relative overflow-hidden rounded-lg bg-slate-950/90 p-2">
              <svg viewBox="0 0 320 130" className="w-full h-auto">
                {/* World Map Graticules */}
                <path
                  d="M 20 65 Q 160 30 300 65 M 20 65 Q 160 100 300 65 M 160 10 L 160 120"
                  stroke="#1e293b"
                  strokeWidth="0.8"
                  fill="none"
                  strokeDasharray="2 2"
                />
                {/* Simplified Continents Schematics */}
                <path
                  d="M 40 40 Q 60 30 80 50 Q 70 70 50 60 Z M 140 35 Q 180 30 200 50 Q 180 70 150 60 Z M 220 50 Q 260 40 280 60 Q 250 80 230 70 Z"
                  fill="#0f172a"
                  stroke="#334155"
                  strokeWidth="0.8"
                />
                {/* Incident Glowing Attack Vectors */}
                <path d="M 60 48 Q 120 20 180 52" fill="none" stroke="#f43f5e" strokeWidth="1.5" strokeDasharray="3 2" />
                <path d="M 240 60 Q 190 25 180 52" fill="none" stroke="#a855f7" strokeWidth="1.2" strokeDasharray="3 2" />

                {/* Hotspot Circles */}
                <circle cx="60" cy="48" r="4" fill="#f43f5e" className="animate-pulse" />
                <circle cx="180" cy="52" r="5" fill="#f43f5e" />
                <circle cx="240" cy="60" r="4" fill="#a855f7" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Blocked Attack Audit Log */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 backdrop-blur-sm">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-rose-400" />
            <div>
              <h3 className="text-sm font-bold text-white">Blocked Attack Audit Log</h3>
              <p className="text-xs text-slate-400">
                Archived security breach attempts with forensic signature diagnostics
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-slate-400">{incidents.length} Incidents Logged</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">Audit ID</th>
                <th className="py-2.5 px-3">Client IP</th>
                <th className="py-2.5 px-3">Prompt Excerpt</th>
                <th className="py-2.5 px-3">Blocked Reason</th>
                <th className="py-2.5 px-3 text-center">Severity</th>
                <th className="py-2.5 px-3 text-center">Resolution</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {incidents.map((inc) => (
                <tr key={inc.audit_id} className="hover:bg-slate-800/30 transition">
                  <td className="py-2.5 px-3 font-bold text-purple-400">{inc.audit_id}</td>
                  <td className="py-2.5 px-3 text-slate-300">{inc.client_ip}</td>
                  <td className="py-2.5 px-3 text-slate-200 font-sans max-w-sm truncate">
                    {inc.prompt_preview}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-sans">{inc.blocked_reason}</td>
                  <td className="py-2.5 px-3 text-center">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                        inc.threat_severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : inc.threat_severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-purple-950 text-purple-300 border border-purple-800'
                      }`}
                    >
                      {inc.threat_severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-center">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                        inc.resolution === 'REJECTED'
                          ? 'text-rose-400 bg-rose-950/60'
                          : 'text-purple-400 bg-purple-950/60'
                      }`}
                    >
                      {inc.resolution}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
