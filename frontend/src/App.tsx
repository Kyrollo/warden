import React, { useState, useEffect } from 'react';
import { AuditIncident, FirewallPolicy, RedTeamPreset, TrafficStreamItem } from './types/warden';
import { fetchIncidents, fetchPolicies, fetchPresets, fetchTrafficStream } from './lib/api';
import { Header } from './components/Header';
import { SocOperationsTab } from './components/SocOperationsTab';
import { RedTeamLabTab } from './components/RedTeamLabTab';
import { PolicyStudioTab } from './components/PolicyStudioTab';
import { ShieldAlert, Bug, Sliders, Radio, Activity } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<'soc' | 'lab' | 'policy'>('soc');
  const [policy, setPolicy] = useState<FirewallPolicy | null>(null);
  const [incidents, setIncidents] = useState<AuditIncident[]>([]);
  const [traffic, setTraffic] = useState<TrafficStreamItem[]>([]);
  const [presets, setPresets] = useState<RedTeamPreset[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [policiesData, incidentsData, trafficData, presetsData] = await Promise.all([
        fetchPolicies(),
        fetchIncidents(),
        fetchTrafficStream(),
        fetchPresets(),
      ]);
      setPolicy(policiesData[0] || null);
      setIncidents(incidentsData);
      setTraffic(trafficData);
      setPresets(presetsData);
    } catch (err: any) {
      console.error('Failed to load Warden data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="min-h-screen bg-[#070913] text-slate-100 font-sans selection:bg-purple-500/30">
      <Header policy={policy} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Navigation Tabs */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950 p-1">
            <button
              onClick={() => setActiveTab('soc')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                activeTab === 'soc'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Radio className="h-4 w-4" />
              <span>SOC Live Operations</span>
            </button>

            <button
              onClick={() => setActiveTab('lab')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                activeTab === 'lab'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Bug className="h-4 w-4" />
              <span>Red-Team Attack Lab</span>
            </button>

            <button
              onClick={() => setActiveTab('policy')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                activeTab === 'policy'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Sliders className="h-4 w-4" />
              <span>Policy Rule Studio</span>
            </button>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Inspection Engine: Armed</span>
          </div>
        </div>

        {/* Tab Views */}
        {loading ? (
          <div className="flex h-72 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30">
            <div className="flex flex-col items-center gap-3">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-purple-500 border-t-transparent" />
              <span className="text-xs text-slate-400 font-mono">
                Arming multi-stage firewall policies...
              </span>
            </div>
          </div>
        ) : (
          <div>
            {activeTab === 'soc' && <SocOperationsTab traffic={traffic} incidents={incidents} />}
            {activeTab === 'lab' && <RedTeamLabTab presets={presets} />}
            {activeTab === 'policy' && (
              <PolicyStudioTab policy={policy} onPolicyUpdated={loadData} />
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
