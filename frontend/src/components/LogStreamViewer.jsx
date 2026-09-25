import React, { useState } from 'react';
import { X, Terminal, CheckCircle, XCircle, Clock, Flame } from 'lucide-react';

export default function LogStreamViewer({ isOpen, onClose, logData }) {
  const [filterAction, setFilterAction] = useState('ALL');
  const [filterApp, setFilterApp] = useState('ALL');
  const [search, setSearch] = useState('');

  if (!isOpen) return null;

  const events = logData?.events || [];
  const stats = logData?.stats || {};
  const appStats = logData?.app_stats || {};

  const filteredEvents = events.filter(e => {
    if (filterAction !== 'ALL' && e.action !== filterAction) return false;
    if (filterApp !== 'ALL' && e.app_id !== filterApp) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        e.src_ip?.includes(q) ||
        e.dst_ip?.includes(q) ||
        e.rule_name?.toLowerCase().includes(q) ||
        e.app_id?.toLowerCase().includes(q) ||
        e.src_zone?.toLowerCase().includes(q) ||
        e.dst_zone?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b101d] border border-slate-700/80 rounded-2xl max-w-5xl w-full shadow-2xl flex flex-col h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="p-4 bg-[#10172b] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-[#fa582d]/20 text-[#fa582d]">
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white">Palo Alto Networks CSV Traffic & Threat Syslog Stream</h3>
              <p className="text-xs text-slate-400">
                Processed {stats.total_events || 0} events ({stats.permitted_flows || 0} Allowed, {stats.denied_flows || 0} Dropped) across {stats.unique_apps || 0} App-IDs
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filter Toolbar */}
        <div className="p-3 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between space-x-3">
          <div className="flex items-center space-x-2">
            {['ALL', 'ALLOW', 'DROP'].map(act => (
              <button
                key={act}
                onClick={() => setFilterAction(act)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  filterAction === act
                    ? 'bg-[#fa582d] text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {act}
              </button>
            ))}

            <span className="text-slate-600">|</span>

            {/* App-ID Quick Filter */}
            <select
              value={filterApp}
              onChange={(e) => setFilterApp(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-[#fa582d]"
            >
              <option value="ALL">All App-IDs</option>
              {Object.keys(appStats).map(app => (
                <option key={app} value={app}>{app} ({appStats[app]})</option>
              ))}
            </select>
          </div>

          <div className="flex-1 max-w-xs">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rule, IP, App-ID, zone..."
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#fa582d]"
            />
          </div>
        </div>

        {/* Log List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-xs">
          {filteredEvents.length === 0 ? (
            <div className="text-center py-12 text-slate-500 italic">No events match the current filter.</div>
          ) : (
            filteredEvents.map((ev, idx) => (
              <div 
                key={idx}
                className={`p-3 rounded-xl border flex items-center justify-between ${
                  ev.action === 'ALLOW'
                    ? 'bg-emerald-950/20 border-emerald-800/40'
                    : 'bg-rose-950/20 border-rose-800/40'
                }`}
              >
                <div className="flex items-center space-x-3">
                  {ev.action === 'ALLOW' ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                  )}

                  <div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        ev.action === 'ALLOW' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
                      }`}>
                        {ev.action}
                      </span>
                      <span className="text-slate-400 text-[11px]">{ev.timestamp}</span>
                      <span className="px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 font-semibold border border-indigo-800 text-[10px]">
                        App: {ev.app_id}
                      </span>
                      <span className="text-cyan-400 font-semibold text-[11px]">{ev.protocol}</span>
                    </div>

                    <div className="mt-1 text-slate-200">
                      <span className="text-amber-400">[{ev.src_zone}]</span> {ev.src_ip}:{ev.src_port} &rarr; <span className="text-emerald-400">[{ev.dst_zone}]</span> {ev.dst_ip}:{ev.dst_port}
                    </div>
                  </div>
                </div>

                <div className="text-right text-[11px]">
                  <span className="text-slate-300 block font-semibold">Rule: "{ev.rule_name}"</span>
                  {ev.bytes > 0 && (
                    <span className="text-emerald-400 block">{ev.bytes.toLocaleString()} bytes</span>
                  )}
                  <span className="text-slate-500 block">Session ID: {ev.session_id}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
