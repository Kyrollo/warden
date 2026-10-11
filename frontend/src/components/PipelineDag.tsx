import React from 'react';
import { ArrowDown, CheckCircle2, ShieldAlert, Zap } from 'lucide-react';

interface PipelineDagProps {
  latencies?: Record<string, number>;
  activeStage?: string;
  isBlocked?: boolean;
}

export const PipelineDag: React.FC<PipelineDagProps> = ({
  latencies,
  activeStage,
  isBlocked,
}) => {
  const sigLat = latencies?.['regex_signature_scan_ms'] ?? 1.8;
  const semLat = latencies?.['semantic_jailbreak_classifier_ms'] ?? 28.5;
  const piiLat = latencies?.['pii_redaction_ms'] ?? 3.4;
  const outLat = latencies?.['output_leakage_ms'] ?? 14.2;
  const totLat = latencies?.['total_pipeline_ms'] ?? (sigLat + semLat + piiLat);

  const stages = [
    { id: 'ingest', name: 'REQUEST INGESTION', lat: '1.2ms', desc: 'Canary & header inspection', color: 'border-slate-700 bg-slate-900/80 text-slate-300' },
    { id: 'sig', name: 'STAGE 1: REGEX SIGNATURES', lat: `${sigLat.toFixed(1)}ms`, desc: 'Direct jailbreaks, DAN, overrides', color: 'border-indigo-600/60 bg-indigo-950/40 text-indigo-300' },
    { id: 'sem', name: 'STAGE 2: SEMANTIC CLASSIFIER', lat: `${semLat.toFixed(1)}ms`, desc: 'Local GPU zero-shot intent analysis', color: 'border-purple-600/60 bg-purple-950/40 text-purple-300' },
    { id: 'pii', name: 'STAGE 3: PII REDACTION', lat: `${piiLat.toFixed(1)}ms`, desc: 'SSN, Cards, Emails, API keys masked', color: 'border-cyan-600/60 bg-cyan-950/40 text-cyan-300' },
    { id: 'action', name: isBlocked ? 'ACTION: BLOCKED (403)' : 'ACTION: ALLOWED / REDACTED', lat: '1.1ms', desc: isBlocked ? 'Adversarial threat neutralized' : 'Sanitized payload forwarded', color: isBlocked ? 'border-rose-600/80 bg-rose-950/60 text-rose-300 font-bold' : 'border-emerald-600/80 bg-emerald-950/60 text-emerald-300 font-bold' },
  ];

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-950/70 p-4 backdrop-blur-sm">
      <div className="mb-3 flex items-center justify-between border-b border-slate-800/80 pb-2">
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-purple-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Multi-Stage Pipeline Latency DAG
          </h4>
        </div>
        <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
          TOTAL: {totLat.toFixed(1)}ms
        </span>
      </div>

      <div className="flex flex-col items-center space-y-2 py-1">
        {stages.map((st, idx) => (
          <React.Fragment key={st.id}>
            <div className={`w-full max-w-sm rounded-lg border p-2.5 transition-all shadow-sm ${st.color}`}>
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="font-bold">{st.name}</span>
                <span className="rounded bg-black/40 px-1.5 py-0.5">{st.lat}</span>
              </div>
              <p className="mt-0.5 text-[10px] text-slate-400 font-sans">{st.desc}</p>
            </div>
            {idx < stages.length - 1 && (
              <ArrowDown className="h-3.5 w-3.5 text-slate-600" />
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
