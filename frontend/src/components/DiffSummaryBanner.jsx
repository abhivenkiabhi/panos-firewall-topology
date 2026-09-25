import React from 'react';
import { PlusCircle, MinusCircle, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';

export default function DiffSummaryBanner({ stats, summaryItems, onSelectEntity }) {
  return (
    <div className="bg-gradient-to-r from-amber-950/40 via-slate-900/90 to-purple-950/30 border-b border-amber-600/30 px-6 py-2.5 flex items-center justify-between z-20">
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-amber-400 font-semibold text-xs uppercase tracking-wider">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Change Request: CR-4910 Diff Active</span>
        </div>
        
        {/* Metric Pills */}
        <div className="flex items-center space-x-3 text-xs">
          <span className="flex items-center space-x-1 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-600/50 text-emerald-300 font-medium">
            <PlusCircle className="w-3.5 h-3.5 text-emerald-400" />
            <span>+{stats?.nodes_added || 1} Subnet & Hosts Added</span>
          </span>

          <span className="flex items-center space-x-1 px-2.5 py-0.5 rounded-full bg-rose-950/80 border border-rose-600/50 text-rose-300 font-medium">
            <MinusCircle className="w-3.5 h-3.5 text-rose-400" />
            <span>-{stats?.nodes_removed || 1} Legacy Decommissioned</span>
          </span>

          <span className="flex items-center space-x-1 px-2.5 py-0.5 rounded-full bg-indigo-950/80 border border-indigo-600/50 text-indigo-300 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
            <span>+2 ACL Policies Enforced</span>
          </span>
        </div>
      </div>

      <div className="flex items-center space-x-3 text-xs text-slate-300">
        <span className="hidden md:inline text-slate-400">
          Showing added items in <strong className="text-emerald-400">Green</strong>, removed in <strong className="text-rose-400">Red Dashed</strong>
        </span>
      </div>
    </div>
  );
}
