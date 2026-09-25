import React, { useState } from 'react';
import { X, Play, CheckCircle2, XCircle, Flame, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function ReachabilitySimulator({ 
  isOpen, 
  onClose, 
  revision, 
  onSimulateComplete,
  prefilledSrc 
}) {
  const [srcIp, setSrcIp] = useState(prefilledSrc || '192.168.10.80');
  const [dstIp, setDstIp] = useState('10.200.50.25');
  const [port, setPort] = useState(443);
  const [protocol, setProtocol] = useState('TCP');
  const [appId, setAppId] = useState('ssl');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  if (!isOpen) return null;

  const presets = [
    { label: 'DMZ ➔ Payment GW (App-ID: ssl)', src: '192.168.10.80', dst: '10.200.50.25', port: 443, proto: 'TCP', app: 'ssl' },
    { label: 'External ➔ DMZ Web (App-ID: ssl)', src: '198.51.100.45', dst: '192.168.10.80', port: 443, proto: 'TCP', app: 'ssl' },
    { label: 'External Scanner (App-ID: ssh)', src: '198.51.100.22', dst: '192.168.10.80', port: 22, proto: 'TCP', app: 'ssh' },
    { label: 'DMZ ➔ Database SQL (App-ID: postgresql)', src: '192.168.10.80', dst: '10.100.1.50', port: 5432, proto: 'TCP', app: 'postgresql' },
    { label: 'App ➔ Database SQL (App-ID: postgresql)', src: '10.100.1.20', dst: '10.100.1.50', port: 5432, proto: 'TCP', app: 'postgresql' },
  ];

  const handleRunSimulation = async (s = srcIp, d = dstIp, p = port, pr = protocol, a = appId) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          src_ip: s,
          dst_ip: d,
          port: parseInt(p),
          protocol: pr,
          app_id: a,
          revision: revision === 'diff' ? 'v2' : revision
        })
      });
      const data = await res.json();
      setResult(data);
      if (onSimulateComplete) {
        onSimulateComplete(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (preset) => {
    setSrcIp(preset.src);
    setDstIp(preset.dst);
    setPort(preset.port);
    setProtocol(preset.proto);
    setAppId(preset.app);
    handleRunSimulation(preset.src, preset.dst, preset.port, preset.proto, preset.app);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0e1424] border border-slate-700/80 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 bg-[#111a30] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-[#fa582d]/20 text-[#fa582d]">
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white">Palo Alto Networks App-ID & Policy Simulator</h3>
              <p className="text-xs text-slate-400">Evaluates Zone-to-Zone policies, Virtual Router FIB, and Layer-7 App-ID</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 overflow-y-auto">
          {/* Quick Presets */}
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-2">
              Common Test Scenarios
            </span>
            <div className="grid grid-cols-2 gap-2">
              {presets.map((p, i) => (
                <button
                  key={i}
                  onClick={() => applyPreset(p)}
                  className="p-2 rounded-xl text-left bg-slate-900/90 hover:bg-[#fa582d]/10 border border-slate-800 hover:border-[#fa582d]/40 transition-all text-xs text-slate-300 hover:text-white"
                >
                  <span className="font-medium block truncate">{p.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Form */}
          <div className="grid grid-cols-2 gap-3 pt-2">
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">Source IP Address</label>
              <input 
                type="text" 
                value={srcIp} 
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="192.168.10.80"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#fa582d]"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">Destination IP Address</label>
              <input 
                type="text" 
                value={dstIp} 
                onChange={(e) => setDstIp(e.target.value)}
                placeholder="10.200.50.25"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#fa582d]"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">Port</label>
              <input 
                type="number" 
                value={port} 
                onChange={(e) => setPort(e.target.value)}
                placeholder="443"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#fa582d]"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">Palo Alto App-ID (Layer 7)</label>
              <select 
                value={appId} 
                onChange={(e) => setAppId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#fa582d]"
              >
                <option value="ssl">ssl</option>
                <option value="web-browsing">web-browsing</option>
                <option value="postgresql">postgresql</option>
                <option value="ssh">ssh</option>
                <option value="telnet">telnet</option>
                <option value="ms-rdp">ms-rdp</option>
                <option value="pan-db-cloud">pan-db-cloud</option>
              </select>
            </div>
          </div>

          <button
            onClick={() => handleRunSimulation()}
            disabled={loading}
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-[#fa582d] to-[#e03a14] hover:brightness-110 text-white font-semibold text-xs shadow-lg shadow-[#fa582d]/30 flex items-center justify-center space-x-2 transition-all"
          >
            {loading ? (
              <span>Evaluating PAN-OS Rules...</span>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                <span>Evaluate Security Policy & Traversal</span>
              </>
            )}
          </button>

          {/* Results Display */}
          {result && (
            <div className={`p-4 rounded-xl border ${
              result.action === 'ALLOW' 
                ? 'bg-emerald-950/40 border-emerald-600/50' 
                : 'bg-rose-950/40 border-rose-600/50'
            } space-y-3`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  {result.action === 'ALLOW' ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-rose-400" />
                  )}
                  <span className={`text-sm font-bold uppercase tracking-wider ${
                    result.action === 'ALLOW' ? 'text-emerald-300' : 'text-rose-300'
                  }`}>
                    {result.action === 'ALLOW' ? 'TRAFFIC ALLOWED' : 'TRAFFIC DROPPED'}
                  </span>
                </div>
                <span className="font-mono text-xs text-slate-300">
                  Rule: <strong>"{result.rule_name}"</strong>
                </span>
              </div>

              <p className="text-xs text-slate-300 font-medium">
                {result.rule_description}
              </p>

              {/* Hop Breakdown */}
              <div className="bg-black/40 rounded-lg p-2.5 space-y-1">
                <span className="text-[10px] font-bold uppercase text-slate-500 block">PAN-OS Inspection Sequence</span>
                {result.path?.map((hop, idx) => (
                  <div key={idx} className="flex items-center space-x-2 text-xs font-mono text-slate-300">
                    <span className="w-4 h-4 rounded-full bg-slate-800 text-slate-400 text-[10px] flex items-center justify-center flex-shrink-0">
                      {idx + 1}
                    </span>
                    <span>{hop}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
