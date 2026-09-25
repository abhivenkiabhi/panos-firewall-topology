import React, { useState, useMemo } from 'react';
import { 
  Shield, 
  Server, 
  Globe, 
  Database, 
  CreditCard, 
  Layers, 
  Key, 
  CheckCircle2,
  XCircle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Flame,
  Route,
  Search,
  Target,
  X
} from 'lucide-react';

export default function TopologyCanvas({ 
  topologyData, 
  revision, 
  showTraffic, 
  selectedNode, 
  onSelectNode,
  simulationResult,
  onClearSimulation
}) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [blastRadiusActive, setBlastRadiusActive] = useState(false);

  // Coordinated positions for PAN-OS architecture
  const layoutCoords = {
    'node-internet-gw': { x: 90, y: 160 },
    'subnet-Untrust': { x: 260, y: 160 },
    'node-PA-NGFW-CORE-01': { x: 500, y: 340 },
    'node-vr-default': { x: 500, y: 440 },
    'subnet-DMZ': { x: 640, y: 130 },
    'host-192-168-10-80': { x: 860, y: 100 },
    'host-192-168-10-85': { x: 860, y: 180 },
    'subnet-Trust-Internal': { x: 480, y: 560 },
    'host-10-100-1-20': { x: 310, y: 670 },
    'host-10-100-1-50': { x: 620, y: 670 },
    'subnet-PCI-Cardholder': { x: 860, y: 340 },
    'host-10-200-50-25': { x: 1070, y: 340 },
    'subnet-Legacy-Test': { x: 170, y: 460 },
    'host-192-168-99-44': { x: 170, y: 590 },
    'subnet-Management': { x: 860, y: 520 },
    'host-10-254-1-10': { x: 1060, y: 520 },
    'subnet-VPN-SiteToSite': { x: 260, y: 340 },
    'vpn-to-aws-vpc': { x: 70, y: 290 },
    'vpn-to-branch-chicago': { x: 70, y: 390 },
  };

  // Connected nodes calculation for Blast Radius Isolation
  const connectedNodeIds = useMemo(() => {
    if (!blastRadiusActive || !selectedNode) return null;
    const direct = new Set([selectedNode.id]);
    topologyData?.edges?.forEach(e => {
      if (e.source === selectedNode.id) direct.add(e.target);
      if (e.target === selectedNode.id) direct.add(e.source);
    });
    // 2-hop expansion
    const twoHop = new Set(direct);
    topologyData?.edges?.forEach(e => {
      if (direct.has(e.source)) twoHop.add(e.target);
      if (direct.has(e.target)) twoHop.add(e.source);
    });
    return twoHop;
  }, [blastRadiusActive, selectedNode, topologyData]);

  // Search filter matching nodes
  const matchingNodeIds = useMemo(() => {
    if (!searchQuery.trim()) return null;
    const q = searchQuery.toLowerCase();
    const matches = new Set();
    topologyData?.nodes?.forEach(n => {
      if (
        n.label?.toLowerCase().includes(q) ||
        n.id?.toLowerCase().includes(q) ||
        n.zone?.toLowerCase().includes(q) ||
        n.metadata?.ip?.toLowerCase().includes(q) ||
        n.metadata?.cidr?.toLowerCase().includes(q)
      ) {
        matches.add(n.id);
      }
    });
    return matches;
  }, [searchQuery, topologyData]);

  const handleMouseDown = (e) => {
    if (e.target.tagName === 'svg' || e.target.id === 'canvas-bg') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const getNodeIcon = (node) => {
    const id = node.id;
    if (id === 'node-PA-NGFW-CORE-01') return <Flame className="w-8 h-8 text-[#fa582d]" />;
    if (id === 'node-vr-default') return <Route className="w-5 h-5 text-amber-400" />;
    if (id.includes('vpn') || id.includes('aws') || id.includes('branch')) return <Globe className="w-5 h-5 text-sky-400" />;
    if (id === 'node-internet-gw') return <Globe className="w-6 h-6 text-rose-400" />;
    if (id.includes('DB') || id.includes('50')) return <Database className="w-5 h-5 text-emerald-400" />;
    if (id.includes('PCI') || id.includes('PAYMENT') || id.includes('25')) return <CreditCard className="w-5 h-5 text-purple-400" />;
    if (id.includes('BASTION') || id.includes('Management')) return <Key className="w-5 h-5 text-blue-400" />;
    if (node.type === 'subnet') return <Layers className="w-5 h-5 text-cyan-400" />;
    return <Server className="w-5 h-5 text-slate-300" />;
  };

  const getNodeClasses = (node) => {
    const isSelected = selectedNode?.id === node.id;
    const diffStatus = node.diff_status;
    const isBlastTarget = selectedNode?.id === node.id && blastRadiusActive;
    const isBlastConnected = connectedNodeIds?.has(node.id) && blastRadiusActive;

    let base = "cursor-pointer transition-all duration-200 select-none ";
    
    if (isBlastTarget) {
      base += "ring-4 ring-amber-400 ring-offset-2 ring-offset-slate-950 scale-105 shadow-2xl shadow-amber-500/50 ";
    } else if (isBlastConnected) {
      base += "ring-2 ring-amber-400/80 ring-offset-1 ring-offset-slate-950 ";
    } else if (isSelected) {
      base += "ring-4 ring-[#fa582d] ring-offset-2 ring-offset-slate-950 scale-105 ";
    }

    if (diffStatus === 'added') {
      return base + "border-2 border-emerald-400 bg-emerald-950/70 shadow-lg shadow-emerald-500/30";
    }
    if (diffStatus === 'removed') {
      return base + "border-2 border-dashed border-rose-500 bg-rose-950/40 opacity-70 shadow-none";
    }
    if (node.id?.includes('vpn') || node.id?.includes('aws') || node.id?.includes('branch')) {
      return base + "border-2 border-sky-500/80 bg-sky-950/50 shadow-lg shadow-sky-500/20";
    }
    if (node.type === 'firewall') {
      return base + "border-2 border-[#fa582d]/80 bg-gradient-to-b from-slate-900 via-slate-900 to-[#fa582d]/20 shadow-xl shadow-[#fa582d]/20";
    }
    if (node.type === 'virtual_router') {
      return base + "border border-amber-600/60 bg-amber-950/30";
    }
    if (node.type === 'subnet') {
      return base + "border border-cyan-800/80 bg-slate-900/90 shadow-md";
    }
    return base + "border border-slate-700 bg-slate-900/80 hover:border-slate-500 shadow-md";
  };

  const isSimulatedPath = (srcId, dstId) => {
    if (!simulationResult) return false;
    const src = simulationResult.src_ip;
    const dst = simulationResult.dst_ip;
    return (srcId?.includes(src.replace(/\./g, '-')) || dstId?.includes(dst.replace(/\./g, '-')));
  };

  return (
    <div 
      className="relative w-full h-[calc(100vh-64px)] bg-[#070b14] overflow-hidden select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
    >
      {/* Grid Background */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-20">
        <defs>
          <pattern id="grid" width="36" height="36" patternUnits="userSpaceOnUse">
            <path d="M 36 0 L 0 0 0 36" fill="none" stroke="#334155" strokeWidth="0.8" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>

      {/* Search & Blast Radius Filter Bar */}
      <div className="absolute top-4 left-6 z-20 flex items-center space-x-3 bg-slate-900/95 border border-slate-800 p-2 rounded-2xl shadow-2xl backdrop-blur">
        <div className="flex items-center space-x-2 px-2.5 py-1.5 bg-slate-950/70 border border-slate-800 rounded-xl">
          <Search className="w-4 h-4 text-slate-400" />
          <input 
            type="text" 
            placeholder="Search IP, Zone, Subnet..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none w-48 font-mono"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-slate-500 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {selectedNode ? (
          <button
            onClick={() => setBlastRadiusActive(!blastRadiusActive)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              blastRadiusActive 
                ? 'bg-amber-500 text-slate-950 shadow-lg shadow-amber-500/30' 
                : 'bg-slate-800 text-amber-400 hover:bg-slate-700 border border-amber-500/30'
            }`}
            title="Isolate 1-hop and 2-hop blast radius"
          >
            <Target className="w-3.5 h-3.5" />
            <span>{blastRadiusActive ? 'Blast Radius: ACTIVE' : 'Isolate Blast Radius'}</span>
          </button>
        ) : (
          <div className="text-[11px] text-slate-400 italic px-2">
            Click any node to calculate blast radius
          </div>
        )}
      </div>

      {/* Canvas Controls */}
      <div className="absolute bottom-6 left-6 z-20 flex items-center space-x-2 bg-slate-900/90 border border-slate-800 p-1.5 rounded-xl shadow-xl backdrop-blur">
        <button 
          onClick={() => setZoom(prev => Math.min(prev + 0.15, 2.0))}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <span className="text-xs font-mono text-slate-400 px-1">{Math.round(zoom * 100)}%</span>
        <button 
          onClick={() => setZoom(prev => Math.max(prev - 0.15, 0.5))}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button 
          onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white"
          title="Reset View"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
      </div>

      {/* Simulation Result Overlay Banner */}
      {simulationResult && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20 max-w-xl w-full bg-slate-900/95 border border-slate-700/80 rounded-2xl p-3 shadow-2xl backdrop-blur flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {simulationResult.action === 'ALLOW' ? (
              <div className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>
            ) : (
              <div className="w-9 h-9 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center">
                <XCircle className="w-5 h-5 text-rose-400" />
              </div>
            )}
            <div>
              <div className="flex items-center space-x-2">
                <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                  simulationResult.action === 'ALLOW' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                }`}>
                  {simulationResult.action === 'ALLOW' ? 'PAN-OS TRAFFIC ALLOWED' : 'PAN-OS TRAFFIC DROPPED'}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {simulationResult.src_ip} &rarr; {simulationResult.dst_ip}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-700">
                  App-ID: {simulationResult.app_id}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                Rule <strong>"{simulationResult.rule_name}"</strong>: <em>{simulationResult.rule_description}</em>
              </p>
            </div>
          </div>
          <button 
            onClick={onClearSimulation}
            className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800"
          >
            Clear
          </button>
        </div>
      )}

      {/* SVG Canvas Content */}
      <div 
        className="w-full h-full"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: '0 0',
          transition: isDragging ? 'none' : 'transform 0.1s ease-out'
        }}
      >
        <svg className="w-[1400px] h-[850px] overflow-visible">
          <defs>
            <linearGradient id="edge-traffic-web" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#06b6d4" />
            </linearGradient>
            <marker id="arrow-panw" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#fa582d" />
            </marker>
            <marker id="arrow-green" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#10b981" />
            </marker>
            <marker id="arrow-purple" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#a855f7" />
            </marker>
          </defs>

          {/* 1. PAN-OS Security Zone Boundary Boxes */}
          {/* DMZ Zone Box */}
          <rect 
            x="580" y="40" width="370" height="210" rx="16" 
            fill="#f59e0b" fillOpacity="0.04" stroke="#f59e0b" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="596" y="66" fill="#f59e0b" fontSize="11" fontWeight="700" letterSpacing="0.05em">PAN-OS ZONE: DMZ (Interface: ethernet1/2)</text>

          {/* Trust-Internal Zone Box */}
          <rect 
            x="240" y="500" width="480" height="240" rx="16" 
            fill="#10b981" fillOpacity="0.04" stroke="#10b981" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="256" y="526" fill="#10b981" fontSize="11" fontWeight="700" letterSpacing="0.05em">PAN-OS ZONE: Trust-Internal (Interface: ethernet1/3)</text>

          {/* PCI-Cardholder Zone Box (V2 or Diff) */}
          {(revision === 'v2' || revision === 'diff') && (
            <>
              <rect 
                x="800" y="270" width="360" height="150" rx="16" 
                fill="#8b5cf6" fillOpacity="0.06" 
                stroke={revision === 'diff' ? '#10b981' : '#8b5cf6'} 
                strokeOpacity="0.5" strokeWidth={revision === 'diff' ? "2" : "1.5"} 
                strokeDasharray="4 4" 
              />
              <text x="816" y="296" fill="#a78bfa" fontSize="11" fontWeight="700" letterSpacing="0.05em">
                {revision === 'diff' ? '★ NEW ZONE: PCI-Cardholder (ethernet1/5)' : 'PAN-OS ZONE: PCI-Cardholder (ethernet1/5)'}
              </text>
            </>
          )}

          {/* Legacy-Test Zone Box (V1 or Diff) */}
          {(revision === 'v1' || revision === 'diff') && (
            <>
              <rect 
                x="80" y="400" width="160" height="260" rx="16" 
                fill="#64748b" fillOpacity="0.04" 
                stroke={revision === 'diff' ? '#f43f5e' : '#64748b'} 
                strokeOpacity={revision === 'diff' ? "0.6" : "0.3"} 
                strokeWidth={revision === 'diff' ? "2" : "1.5"} 
                strokeDasharray="6 4" 
              />
              <text x="96" y="426" fill={revision === 'diff' ? '#fb7185' : '#94a3b8'} fontSize="10" fontWeight="700" letterSpacing="0.05em">
                {revision === 'diff' ? '✖ DECOMMISSIONED: Legacy-Test' : 'ZONE: Legacy-Test'}
              </text>
            </>
          )}

          {/* Management Zone Box */}
          <rect 
            x="780" y="460" width="360" height="140" rx="16" 
            fill="#3b82f6" fillOpacity="0.04" stroke="#3b82f6" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="796" y="486" fill="#60a5fa" fontSize="11" fontWeight="700" letterSpacing="0.05em">PAN-OS ZONE: Management (ethernet1/8)</text>

          {/* VPN-SiteToSite Zone Box */}
          <rect 
            x="45" y="240" width="280" height="200" rx="16" 
            fill="#0284c7" fillOpacity="0.04" stroke="#0284c7" strokeOpacity="0.3" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="60" y="266" fill="#38bdf8" fontSize="11" fontWeight="700" letterSpacing="0.05em">PAN-OS ZONE: VPN-SiteToSite (tunnel.1 & tunnel.2)</text>

          {/* 2. Physical & Logical Links */}
          {topologyData?.edges?.map((edge) => {
            const srcCoord = layoutCoords[edge.source];
            const dstCoord = layoutCoords[edge.target];
            if (!srcCoord || !dstCoord) return null;

            if (revision === 'v2' && (edge.source?.includes('Legacy') || edge.target?.includes('Legacy'))) return null;
            if (revision === 'v1' && (edge.source?.includes('PCI') || edge.target?.includes('PCI'))) return null;

            const isDiffAdded = edge.diff_status === 'added';
            const isDiffRemoved = edge.diff_status === 'removed';
            const isSimPath = isSimulatedPath(edge.source, edge.target);
            const isBlastEdge = connectedNodeIds && connectedNodeIds.has(edge.source) && connectedNodeIds.has(edge.target) && blastRadiusActive;
            const isEdgeDimmed = (connectedNodeIds && (!connectedNodeIds.has(edge.source) || !connectedNodeIds.has(edge.target))) ||
                                 (matchingNodeIds && (!matchingNodeIds.has(edge.source) && !matchingNodeIds.has(edge.target)));

            let strokeColor = "#334155";
            let strokeWidth = "2";
            let dashArray = "none";

            if (isSimPath) {
              strokeColor = "#fa582d";
              strokeWidth = "3.5";
            } else if (isBlastEdge) {
              strokeColor = "#f59e0b";
              strokeWidth = "3";
              dashArray = "4 4";
            } else if (isDiffAdded) {
              strokeColor = "#10b981";
              strokeWidth = "2.5";
            } else if (isDiffRemoved) {
              strokeColor = "#f43f5e";
              strokeWidth = "2";
              dashArray = "4 4";
            } else if (edge.type === 'interface_link') {
              strokeColor = "#475569";
              strokeWidth = "2.5";
            }

            return (
              <g key={edge.id} opacity={isEdgeDimmed ? 0.12 : 1} style={{ transition: 'opacity 0.25s ease' }}>
                <line 
                  x1={srcCoord.x} 
                  y1={srcCoord.y} 
                  x2={dstCoord.x} 
                  y2={dstCoord.y} 
                  stroke={strokeColor} 
                  strokeWidth={strokeWidth} 
                  strokeDasharray={dashArray} 
                />
                {edge.label && (
                  <text 
                    x={(srcCoord.x + dstCoord.x) / 2} 
                    y={(srcCoord.y + dstCoord.y) / 2 - 6} 
                    fill="#94a3b8" 
                    fontSize="10" 
                    textAnchor="middle" 
                    className="font-mono bg-slate-900 px-1"
                  >
                    {edge.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* 3. Dynamic Animated App-ID Traffic Flows */}
          {showTraffic && (
            <>
              {/* Traffic Flow 1: App-ID ssl & web-browsing */}
              <path 
                d="M 90 160 Q 380 90 860 100" 
                fill="none" 
                stroke="url(#edge-traffic-web)" 
                strokeWidth="3" 
                className="animate-traffic"
                markerEnd="url(#arrow-green)"
              />
              <text x="360" y="80" fill="#34d399" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: ssl / web-browsing [Allow-Inbound-Web]
              </text>

              {/* Traffic Flow 2: App-ID web-browsing */}
              <path 
                d="M 860 100 Q 500 300 310 670" 
                fill="none" 
                stroke="#06b6d4" 
                strokeWidth="2.5" 
                className="animate-traffic"
              />
              <text x="590" y="440" fill="#22d3ee" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: web-browsing [Allow-DMZ-to-App]
              </text>

              {/* Traffic Flow 3: App-ID postgresql */}
              <path 
                d="M 310 670 L 620 670" 
                fill="none" 
                stroke="#818cf8" 
                strokeWidth="2.5" 
                className="animate-traffic"
              />
              <text x="465" y="660" fill="#a5b4fc" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: postgresql [Allow-App-to-DB]
              </text>

              {/* Traffic Flow 4: App-ID ssl to PCI (V2 or Diff) */}
              {(revision === 'v2' || revision === 'diff') && (
                <g>
                  <path 
                    d="M 860 100 Q 940 200 1070 340" 
                    fill="none" 
                    stroke="#a855f7" 
                    strokeWidth="3" 
                    className="animate-traffic"
                    markerEnd="url(#arrow-purple)"
                  />
                  <text x="940" y="235" fill="#c084fc" fontSize="10" fontWeight="700" className="font-mono">
                    App-ID: ssl [Allow-DMZ-to-Payment-GW]
                  </text>
                </g>
              )}
            </>
          )}

          {/* 4. Render PAN-OS Topology Nodes */}
          {topologyData?.nodes?.map((node) => {
            const coord = layoutCoords[node.id];
            if (!coord) return null;

            if (revision === 'v2' && node.id.includes('Legacy')) return null;
            if (revision === 'v1' && node.id.includes('PCI')) return null;

            const isFw = node.type === 'firewall';
            const isVR = node.type === 'virtual_router';
            const isSubnet = node.type === 'subnet';
            const isEndpoint = node.type === 'endpoint';
            const isDiffAdded = node.diff_status === 'added';
            const isDiffRemoved = node.diff_status === 'removed';

            let w = isFw ? 230 : isVR ? 180 : isSubnet ? 165 : 170;
            let h = isFw ? 96 : isVR ? 56 : isSubnet ? 64 : 64;

            const isDimmed = (connectedNodeIds && !connectedNodeIds.has(node.id)) ||
                             (matchingNodeIds && !matchingNodeIds.has(node.id));

            return (
              <foreignObject
                key={node.id}
                x={coord.x - w / 2}
                y={coord.y - h / 2}
                width={w}
                height={h}
                className="overflow-visible"
                style={{ opacity: isDimmed ? 0.15 : 1, transition: 'opacity 0.25s ease' }}
              >
                <div
                  onClick={() => onSelectNode(node)}
                  className={`rounded-2xl p-2.5 flex items-center space-x-3 ${getNodeClasses(node)}`}
                >
                  <div className={`p-2 rounded-xl flex items-center justify-center ${
                    isFw ? 'bg-[#fa582d]/20 text-[#fa582d]' : isVR ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-800 text-slate-300'
                  }`}>
                    {getNodeIcon(node)}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-100 truncate block">
                        {node.label?.split('\n')[0]}
                      </span>
                    </div>

                    {isFw && (
                      <div className="mt-0.5">
                        <span className="text-[10px] text-[#fa582d] font-bold tracking-wider block">PA-3410 PAN-OS 11.1</span>
                        <div className="flex items-center space-x-1.5 text-[10px] text-slate-400">
                          <span>{node.metadata?.interfaces?.length || 5} Ports</span>
                          <span>•</span>
                          <span className="text-emerald-400 font-mono">App-ID Active</span>
                        </div>
                      </div>
                    )}

                    {isVR && (
                      <span className="text-[10px] font-mono text-amber-400 block truncate">
                        Default VR (FIB)
                      </span>
                    )}

                    {isSubnet && (
                      <span className="text-[10px] font-mono text-cyan-400 block truncate">
                        {node.metadata?.cidr}
                      </span>
                    )}

                    {isEndpoint && (
                      <div>
                        <span className="text-[10px] font-mono text-emerald-400 block truncate">
                          {node.metadata?.ip}
                        </span>
                        {node.metadata?.mac && (
                          <span className="text-[9px] font-mono text-slate-500 block truncate">
                            {node.metadata.mac}
                          </span>
                        )}
                      </div>
                    )}

                    {isDiffAdded && (
                      <span className="inline-block mt-0.5 text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        + Added (CR-4910)
                      </span>
                    )}
                    {isDiffRemoved && (
                      <span className="inline-block mt-0.5 text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        ✖ Decommissioned
                      </span>
                    )}
                  </div>
                </div>
              </foreignObject>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
