import React from 'react';
import { 
  Shield, 
  Layers, 
  GitCompare, 
  Play, 
  MessageSquare, 
  Terminal, 
  Activity,
  Flame,
  Cpu,
  FolderTree
} from 'lucide-react';

export default function Header({ 
  revision, 
  setRevision, 
  showTraffic, 
  setShowTraffic,
  onOpenSimulator,
  onOpenChat,
  onOpenLogs,
  onOpenTree,
  isTreeOpen
}) {
  return (
    <header className="h-16 bg-[#0b0f19] border-b border-slate-800 px-6 flex items-center justify-between select-none z-30 shadow-md">
      {/* Brand & Platform Info */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#e03a14] via-[#fa582d] to-amber-500 flex items-center justify-center shadow-lg shadow-[#fa582d]/25">
          <Flame className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-extrabold text-sm tracking-tight text-white uppercase">
              Palo Alto Networks
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#fa582d]/15 text-[#fa582d] font-bold border border-[#fa582d]/30">
              PAN-OS 11.1
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
              PA-3410
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium">
            Strata Topology Viewer & App-ID Policy Intelligence
          </p>
        </div>
      </div>

      {/* Revision Switcher Tabs */}
      <div className="flex items-center bg-[#131b2e] p-1 rounded-xl border border-slate-700/80">
        <button
          onClick={() => setRevision('v1')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            revision === 'v1'
              ? 'bg-[#fa582d] text-white shadow-md shadow-[#fa582d]/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Commit V1 (Baseline)</span>
        </button>

        <button
          onClick={() => setRevision('v2')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            revision === 'v2'
              ? 'bg-[#fa582d] text-white shadow-md shadow-[#fa582d]/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Commit V2 (CR-4910)</span>
        </button>

        <button
          onClick={() => setRevision('diff')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            revision === 'diff'
              ? 'bg-amber-500 text-slate-950 font-bold shadow-md shadow-amber-500/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Commit Diff View</span>
        </button>
      </div>

      {/* Action Toolbar */}
      <div className="flex items-center space-x-2.5">
        {/* Toggle Live Traffic Flows */}
        <button
          onClick={() => setShowTraffic(!showTraffic)}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
            showTraffic
              ? 'bg-emerald-950/60 border-emerald-600/50 text-emerald-300'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className={`w-3.5 h-3.5 ${showTraffic ? 'animate-pulse text-emerald-400' : ''}`} />
          <span>App-ID Flows</span>
        </button>

        {/* Hierarchy Tree Navigator Drawer */}
        <button
          onClick={onOpenTree}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all shadow-sm ${
            isTreeOpen 
              ? 'bg-[#fa582d]/20 border-[#fa582d] text-white shadow-[#fa582d]/20'
              : 'bg-slate-900 hover:bg-slate-800 border-slate-700/80 text-slate-200 hover:text-white'
          }`}
          title="Open PAN-OS 5-Tier Containment Tree"
        >
          <FolderTree className="w-3.5 h-3.5 text-[#fa582d]" />
          <span>Hierarchy Tree</span>
        </button>

        {/* Reachability Simulator Modal */}
        <button
          onClick={onOpenSimulator}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-200 hover:text-white transition-all shadow-sm"
        >
          <Play className="w-3.5 h-3.5 text-[#fa582d]" />
          <span>Policy Simulator</span>
        </button>

        {/* Live Syslog Stream Viewer */}
        <button
          onClick={onOpenLogs}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-200 hover:text-white transition-all shadow-sm"
        >
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>PAN-OS Logs</span>
        </button>

        {/* Customer / TAC Assistant Drawer */}
        <button
          onClick={onOpenChat}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-[#fa582d] to-[#e03a14] hover:brightness-110 text-white transition-all shadow-md shadow-[#fa582d]/25"
        >
          <MessageSquare className="w-3.5 h-3.5" />
          <span>PAN-OS Assistant</span>
        </button>
      </div>
    </header>
  );
}
