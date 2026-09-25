import React from 'react';
import { X, Flame, Terminal, Activity, CheckCircle, XCircle, Route } from 'lucide-react';

export default function InspectorDrawer({ 
  node, 
  onClose, 
  configData, 
  logData,
  onSimulateWithNode 
}) {
  if (!node) return null;

  const nodeIp = node.metadata?.ip || node.metadata?.cidr;
  const isFw = node.type === 'firewall';
  const isVR = node.type === 'virtual_router';

  // Filter relevant PAN-OS security rules
  const relevantRules = configData?.parsed?.security_rules?.filter(rule => {
    if (isFw || isVR) return true;
    if (node.zone && (rule.from_zone === node.zone || rule.to_zone === node.zone)) return true;
    if (nodeIp && (rule.source?.includes(nodeIp) || rule.destination?.includes(nodeIp))) return true;
    return false;
  }) || [];

  // Filter relevant PAN-OS syslog events
  const relevantLogs = logData?.events?.filter(ev => {
    if (isFw || isVR) return true;
    if (nodeIp && (ev.src_ip === nodeIp || ev.dst_ip === nodeIp)) return true;
    if (node.zone && (ev.src_zone === node.zone || ev.dst_zone === node.zone)) return true;
    return false;
  }) || [];

  return (
    <aside className="fixed top-16 right-0 w-96 h-[calc(100vh-64px)] bg-[#0d1322]/98 border-l border-slate-800 shadow-2xl flex flex-col z-40 backdrop-blur overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Drawer Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-[#11192d]">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-[#fa582d]/20 text-[#fa582d]">
            {isVR ? <Route className="w-5 h-5" /> : <Flame className="w-5 h-5" />}
          </div>
          <div>
            <h3 className="text-sm font-bold text-white truncate max-w-[200px]">{node.label?.split('\n')[0]}</h3>
            <span className="text-[11px] text-slate-400 font-mono">
              Zone: <strong className="text-slate-200">{node.zone || 'Global'}</strong>
            </span>
          </div>
        </div>
        <button 
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Node Properties */}
        <div className="bg-slate-900/80 rounded-xl p-3 border border-slate-800/80 space-y-2">
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">PAN-OS Object Details</h4>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-slate-500 block text-[10px]">Type</span>
              <span className="font-semibold text-slate-200 capitalize">{node.type}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">IP / Subnet</span>
              <span className="font-mono text-cyan-400">{nodeIp || 'N/A'}</span>
            </div>
            {node.metadata?.interface && (
              <div>
                <span className="text-slate-500 block text-[10px]">Interface</span>
                <span className="font-mono text-slate-300">{node.metadata.interface}</span>
              </div>
            )}
            {node.metadata?.mac && (
              <div>
                <span className="text-slate-500 block text-[10px]">MAC Address</span>
                <span className="font-mono text-slate-300">{node.metadata.mac}</span>
              </div>
            )}
            {node.diff_status && (
              <div>
                <span className="text-slate-500 block text-[10px]">Diff Status</span>
                <span className={`font-semibold uppercase text-[10px] ${
                  node.diff_status === 'added' ? 'text-emerald-400' : 'text-rose-400'
                }`}>
                  {node.diff_status}
                </span>
              </div>
            )}
          </div>

          {node.type === 'endpoint' && (
            <button
              onClick={() => onSimulateWithNode(node.metadata?.ip)}
              className="w-full mt-2 py-1.5 px-3 rounded-lg bg-[#fa582d]/20 hover:bg-[#fa582d]/30 border border-[#fa582d]/40 text-[#fa582d] text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all"
            >
              <Activity className="w-3.5 h-3.5 text-[#fa582d]" />
              <span>Simulate App-ID Path from Here</span>
            </button>
          )}
        </div>

        {/* Applied Security Policies */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              PAN-OS Security Policies ({relevantRules.length})
            </h4>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {relevantRules.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No specific rule matched (Interzone drop / Intrazone allow applies).</p>
            ) : (
              relevantRules.map((rule, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] font-bold text-white">
                      "{rule.name}"
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      rule.action === 'ALLOW' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {rule.action}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-300 font-mono">
                    {rule.from_zone} &rarr; {rule.to_zone}
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {rule.applications?.map((app, j) => (
                      <span key={j} className="px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-mono">
                        App: {app}
                      </span>
                    ))}
                  </div>
                  {rule.description && (
                    <p className="text-[10px] text-slate-400 italic pt-0.5">{rule.description}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* PAN-OS CSV Syslog Events */}
        <div>
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Recent PAN-OS Traffic Logs ({relevantLogs.length})
          </h4>

          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
            {relevantLogs.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No recent flow records in log window.</p>
            ) : (
              relevantLogs.map((log, i) => (
                <div key={i} className="p-2 rounded bg-slate-950/60 border border-slate-800/80 text-[11px] font-mono flex items-center justify-between">
                  <div className="flex items-center space-x-1.5 truncate">
                    {log.action === 'ALLOW' ? (
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                    )}
                    <span className="truncate text-slate-300">
                      {log.src_ip} &rarr; {log.dst_port}
                    </span>
                    <span className="text-[10px] px-1 rounded bg-slate-800 text-indigo-300">
                      {log.app_id}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500 flex-shrink-0 ml-1">
                    {log.rule_name}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Raw PAN-OS 'set' CLI Excerpt */}
        <div>
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center space-x-1.5">
            <Terminal className="w-3.5 h-3.5 text-[#fa582d]" />
            <span>PAN-OS 'set' Command Excerpt</span>
          </h4>
          <pre className="p-2.5 rounded-lg bg-black/60 border border-slate-800 text-[10px] font-mono text-orange-200/90 overflow-x-auto whitespace-pre leading-relaxed">
{isFw ? `set deviceconfig system hostname PA-NGFW-CORE-01
set network virtual-router default interface [ ethernet1/1 ethernet1/2 ethernet1/3 ethernet1/5 ]
set zone Untrust network layer3 ethernet1/1
set zone DMZ network layer3 ethernet1/2
set zone Trust-Internal network layer3 ethernet1/3
set zone PCI-Cardholder network layer3 ethernet1/5` : isVR ? `set network virtual-router default routing-table ip static-route "Default-Internet-Gateway" destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route "Route-DMZ" interface ethernet1/2
set network virtual-router default routing-table ip static-route "Route-Trust-Internal" interface ethernet1/3` : `set network interface ethernet ${node.metadata?.interface || 'ethernet1/2'} layer3 ip ${nodeIp}
set zone ${node.zone || 'DMZ'} network layer3 ${node.metadata?.interface || 'ethernet1/2'}`}
          </pre>
        </div>
      </div>
    </aside>
  );
}
