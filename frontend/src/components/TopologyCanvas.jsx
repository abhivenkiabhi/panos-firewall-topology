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
  X,
  ChevronRight,
  Filter
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
  const [hierarchyDepth, setHierarchyDepth] = useState('all'); // 'all' | 'zones' | 'subnets'

  // 5-Tier Hierarchical layout coordinates for PAN-OS architecture
  const layoutCoords = {
    // Tier 1: External Boundaries & WAN (Ingress)
    'node-internet-gw': { x: 140, y: 170 },
    'subnet-Untrust': { x: 140, y: 280 },
    'vpn-to-aws-vpc': { x: 140, y: 430 },
    'vpn-to-branch-chicago': { x: 140, y: 550 },
    'subnet-VPN-SiteToSite': { x: 140, y: 670 },

    // Tier 2: Enforcement Hub & Virtual Router Core
    'node-PA-NGFW-CORE-01': { x: 420, y: 310 },
    'node-vr-default': { x: 420, y: 470 },

    // Tier 3: Demilitarized Zone (DMZ Web Tier)
    'subnet-DMZ': { x: 700, y: 190 },
    'host-192-168-10-80': { x: 700, y: 300 },
    'host-192-168-10-85': { x: 700, y: 410 },

    // Tier 4: Enterprise Trust & PCI Restricted Zone
    'subnet-Trust-Internal': { x: 990, y: 170 },
    'host-10-100-1-20': { x: 990, y: 270 },
    'host-10-100-1-50': { x: 990, y: 370 },
    'subnet-PCI-Cardholder': { x: 990, y: 510 },
    'host-10-200-50-25': { x: 990, y: 620 },
    'subnet-Legacy-Test': { x: 990, y: 750 },
    'host-192-168-99-44': { x: 990, y: 850 },

    // Tier 5: Management Plane & OOB
    'subnet-Management': { x: 1280, y: 310 },
    'host-10-254-1-10': { x: 1280, y: 430 },
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

  // Depth filter check
  const isDepthFiltered = (node) => {
    if (hierarchyDepth === 'all') return false;
    if (hierarchyDepth === 'zones') {
      return node.type === 'endpoint' || node.type === 'gateway';
    }
    if (hierarchyDepth === 'subnets') {
      return node.type === 'endpoint';
    }
    return false;
  };

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
    if (node.type === 'subnet') return <Layers className="w-5 h-5 text-indigo-400" />;
    return <Server className="w-5 h-5 text-slate-300" />;
  };

  const getNodeClasses = (node) => {
    const isSelected = selectedNode?.id === node.id;
    const isDiffAdded = node.diff_status === 'added';
    const isDiffRemoved = node.diff_status === 'removed';
    const isFw = node.type === 'firewall';
    const isVR = node.type === 'virtual_router';
    const isSubnet = node.type === 'subnet';
    const isBlastTarget = blastRadiusActive && selectedNode?.id === node.id;
    const isBlastConnected = blastRadiusActive && connectedNodeIds?.has(node.id) && !isBlastTarget;

    let base = "cursor-pointer transition-all duration-200 select-none shadow-xl border relative ";

    if (isBlastTarget) {
      base += "ring-4 ring-amber-400 ring-offset-2 ring-offset-slate-950 scale-105 z-30 ";
    } else if (isBlastConnected) {
      base += "ring-2 ring-amber-400/80 ring-offset-1 ring-offset-slate-950 scale-102 z-20 ";
    }

    if (isSelected && !blastRadiusActive) {
      base += "ring-2 ring-[#fa582d] ring-offset-2 ring-offset-slate-950 scale-105 z-20 ";
    }

    if (isFw) {
      return base + "bg-gradient-to-b from-slate-900 via-slate-900 to-black border-[#fa582d]/50 hover:border-[#fa582d] shadow-[#fa582d]/20";
    }

    if (isVR) {
      return base + "bg-gradient-to-b from-slate-900 to-amber-950/40 border-amber-500/50 hover:border-amber-400 shadow-amber-500/20";
    }

    if (isDiffAdded) {
      return base + "bg-emerald-950/70 border-emerald-500 shadow-emerald-500/30 text-emerald-100 hover:border-emerald-400";
    }

    if (isDiffRemoved) {
      return base + "bg-rose-950/70 border-rose-500/80 border-dashed text-rose-300 opacity-75 hover:border-rose-400";
    }

    if (isSubnet) {
      return base + "bg-slate-900/90 border-indigo-900/60 hover:border-indigo-500/80 text-slate-200";
    }

    return base + "bg-slate-900/95 border-slate-800 hover:border-slate-600 text-slate-200";
  };

  const isSimulatedPath = (srcId, dstId) => {
    if (!simulationResult) return false;
    const src = simulationResult.src_ip;
    const dst = simulationResult.dst_ip;
    return (srcId?.includes(src.replace(/\./g, '-')) || dstId?.includes(dst.replace(/\./g, '-')));
  };

  // Breadcrumbs derivation
  const breadcrumbs = useMemo(() => {
    if (!selectedNode) return null;
    const crumbs = [
      { label: 'PA-NGFW-CORE-01', type: 'firewall' },
      { label: 'VR: default', type: 'vr' }
    ];
    if (selectedNode.type === 'firewall') return [crumbs[0]];
    if (selectedNode.type === 'virtual_router') return crumbs;

    const zone = selectedNode.zone || (selectedNode.id?.includes('Untrust') ? 'Untrust' : 
                                selectedNode.id?.includes('VPN') ? 'VPN-SiteToSite' :
                                selectedNode.id?.includes('DMZ') ? 'DMZ' :
                                selectedNode.id?.includes('Trust') ? 'Trust-Internal' :
                                selectedNode.id?.includes('PCI') ? 'PCI-Cardholder' :
                                selectedNode.id?.includes('Management') ? 'Management' : 'Zone');
    crumbs.push({ label: `Zone: ${zone}`, type: 'zone' });

    if (selectedNode.type === 'subnet') {
      crumbs.push({ label: selectedNode.metadata?.cidr || selectedNode.label?.split('\n')[0], type: 'subnet' });
    } else {
      if (selectedNode.metadata?.interface) {
        crumbs.push({ label: selectedNode.metadata.interface, type: 'interface' });
      }
      crumbs.push({ label: selectedNode.label?.split('\n')[0] || selectedNode.id, type: 'endpoint' });
    }
    return crumbs;
  }, [selectedNode]);

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

      {/* Top Floating Controls: Search, Blast Radius, & Hierarchy Depth */}
      <div className="absolute top-4 left-6 z-20 flex flex-col space-y-2">
        <div className="flex items-center space-x-3 bg-slate-900/95 border border-slate-800 p-2 rounded-2xl shadow-2xl backdrop-blur">
          {/* Instant Search Bar */}
          <div className="flex items-center space-x-2 px-2.5 py-1.5 bg-slate-950/70 border border-slate-800 rounded-xl">
            <Search className="w-4 h-4 text-slate-400" />
            <input 
              type="text" 
              placeholder="Search IP, Zone, Subnet..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none w-44 font-mono"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} className="text-slate-500 hover:text-white">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Blast Radius Isolation Toggle */}
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
              <span>{blastRadiusActive ? 'Blast Radius: ON' : 'Isolate Blast'}</span>
            </button>
          ) : (
            <div className="text-[11px] text-slate-500 italic px-2">
              Select node for blast radius
            </div>
          )}

          {/* Vertical Separator */}
          <div className="h-6 w-[1px] bg-slate-800" />

          {/* Hierarchy Depth Filter */}
          <div className="flex items-center bg-slate-950/60 p-1 rounded-xl border border-slate-800 space-x-1">
            <button
              onClick={() => setHierarchyDepth('all')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${
                hierarchyDepth === 'all'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Show all architectural layers"
            >
              All Tiers
            </button>
            <button
              onClick={() => setHierarchyDepth('zones')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${
                hierarchyDepth === 'zones'
                  ? 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Show high-level security zones & router core"
            >
              Zones Only
            </button>
            <button
              onClick={() => setHierarchyDepth('subnets')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${
                hierarchyDepth === 'subnets'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Show subnets & interfaces routing plane"
            >
              Subnets
            </button>
          </div>
        </div>

        {/* Hierarchical Breadcrumb Trail */}
        {breadcrumbs && (
          <div className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900/90 border border-slate-800/90 rounded-xl shadow-lg backdrop-blur w-fit animate-in fade-in duration-200">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold mr-1">Hierarchy:</span>
            {breadcrumbs.map((crumb, idx) => (
              <React.Fragment key={idx}>
                <span className={`text-[11px] font-mono font-medium ${
                  idx === breadcrumbs.length - 1 ? 'text-[#fa582d] font-bold' : 'text-slate-300'
                }`}>
                  {crumb.label}
                </span>
                {idx < breadcrumbs.length - 1 && (
                  <ChevronRight className="w-3 h-3 text-slate-600" />
                )}
              </React.Fragment>
            ))}
            <button 
              onClick={() => onSelectNode(null)}
              className="ml-2 text-slate-500 hover:text-white"
              title="Clear selection"
            >
              <X className="w-3 h-3" />
            </button>
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
        <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-20 bg-slate-900/95 border border-slate-700 p-4 rounded-2xl shadow-2xl backdrop-blur-md flex items-center space-x-6 min-w-[580px]">
          <div className="flex items-center space-x-3">
            {simulationResult.action === 'ALLOW' ? (
              <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                <CheckCircle2 className="w-6 h-6" />
              </div>
            ) : (
              <div className="p-2 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40">
                <XCircle className="w-6 h-6" />
              </div>
            )}
            <div>
              <div className="flex items-center space-x-2">
                <span className={`font-black text-sm tracking-wide ${
                  simulationResult.action === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'
                }`}>
                  POLICY {simulationResult.action}
                </span>
                <span className="text-xs text-slate-400">
                  via Rule <span className="font-mono text-white font-semibold">"{simulationResult.rule_name}"</span>
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                {simulationResult.explanation}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 border-l border-slate-800 pl-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">App-ID</span>
              <span className="text-[#fa582d] font-bold">{simulationResult.app_id}</span>
            </div>
            <div className="ml-3">
              <span className="text-slate-500 block text-[10px]">Port</span>
              <span className="text-slate-300">{simulationResult.port}/{simulationResult.protocol}</span>
            </div>
          </div>

          <button
            onClick={onClearSimulation}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* SVG Rendering Canvas */}
      <div 
        id="canvas-bg"
        className="w-full h-full cursor-grab active:cursor-grabbing"
      >
        <svg 
          className="w-full h-full"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
            transition: isDragging ? 'none' : 'transform 0.1s ease-out'
          }}
        >
          <defs>
            <linearGradient id="flow-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#fa582d" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.8" />
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

          {/* 5-Tier Vertical Column Dividers */}
          <line x1="280" y1="40" x2="280" y2="920" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
          <line x1="560" y1="40" x2="560" y2="920" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
          <line x1="840" y1="40" x2="840" y2="920" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
          <line x1="1140" y1="40" x2="1140" y2="920" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />

          {/* Tier Header Badges */}
          <g>
            {/* Tier 1 */}
            <rect x="40" y="50" width="220" height="26" rx="6" fill="#0f172a" stroke="#334155" strokeWidth="1" />
            <text x="52" y="67" fill="#94a3b8" fontSize="10" fontWeight="800" letterSpacing="0.08em">TIER 1: EXTERNAL / WAN INGRESS</text>

            {/* Tier 2 */}
            <rect x="310" y="50" width="220" height="26" rx="6" fill="#0f172a" stroke="#fa582d" strokeOpacity="0.4" strokeWidth="1" />
            <text x="325" y="67" fill="#fa582d" fontSize="10" fontWeight="800" letterSpacing="0.08em">TIER 2: NGFW CORE & ROUTING</text>

            {/* Tier 3 */}
            <rect x="590" y="50" width="220" height="26" rx="6" fill="#0f172a" stroke="#f59e0b" strokeOpacity="0.4" strokeWidth="1" />
            <text x="605" y="67" fill="#f59e0b" fontSize="10" fontWeight="800" letterSpacing="0.08em">TIER 3: DEMILITARIZED (DMZ)</text>

            {/* Tier 4 */}
            <rect x="870" y="50" width="240" height="26" rx="6" fill="#0f172a" stroke="#10b981" strokeOpacity="0.4" strokeWidth="1" />
            <text x="885" y="67" fill="#34d399" fontSize="10" fontWeight="800" letterSpacing="0.08em">TIER 4: ENTERPRISE TRUST & PCI</text>

            {/* Tier 5 */}
            <rect x="1170" y="50" width="220" height="26" rx="6" fill="#0f172a" stroke="#3b82f6" strokeOpacity="0.4" strokeWidth="1" />
            <text x="1185" y="67" fill="#60a5fa" fontSize="10" fontWeight="800" letterSpacing="0.08em">TIER 5: MANAGEMENT PLANE</text>
          </g>

          {/* 1. PAN-OS Security Zone Boundary Boxes */}
          {/* Untrust Zone Box */}
          <rect 
            x="40" y="95" width="220" height="230" rx="14" 
            fill="#f43f5e" fillOpacity="0.03" stroke="#f43f5e" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="52" y="118" fill="#fb7185" fontSize="10" fontWeight="700">PAN-OS ZONE: Untrust (ethernet1/1)</text>

          {/* VPN-SiteToSite Zone Box */}
          <rect 
            x="40" y="350" width="220" height="360" rx="14" 
            fill="#0284c7" fillOpacity="0.03" stroke="#0284c7" strokeOpacity="0.3" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="52" y="373" fill="#38bdf8" fontSize="10" fontWeight="700">PAN-OS ZONE: VPN-SiteToSite (tunnel.1 & .2)</text>

          {/* DMZ Zone Box */}
          <rect 
            x="590" y="110" width="220" height="340" rx="14" 
            fill="#f59e0b" fillOpacity="0.03" stroke="#f59e0b" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="602" y="133" fill="#fbbf24" fontSize="10" fontWeight="700">PAN-OS ZONE: DMZ (ethernet1/2)</text>

          {/* Trust-Internal Zone Box */}
          <rect 
            x="870" y="95" width="240" height="320" rx="14" 
            fill="#10b981" fillOpacity="0.03" stroke="#10b981" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="882" y="118" fill="#34d399" fontSize="10" fontWeight="700">PAN-OS ZONE: Trust-Internal (ethernet1/3)</text>

          {/* PCI-Cardholder Zone Box (V2 or Diff) */}
          {(revision === 'v2' || revision === 'diff') && (
            <>
              <rect 
                x="870" y="440" width="240" height="220" rx="14" 
                fill="#8b5cf6" fillOpacity="0.04" 
                stroke={revision === 'diff' ? '#10b981' : '#8b5cf6'} 
                strokeOpacity="0.4" strokeWidth={revision === 'diff' ? "2" : "1.5"} 
                strokeDasharray="4 4" 
              />
              <text x="882" y="463" fill="#c084fc" fontSize="10" fontWeight="700">
                {revision === 'diff' ? '★ NEW ZONE: PCI-Cardholder (ethernet1/5)' : 'PAN-OS ZONE: PCI-Cardholder (ethernet1/5)'}
              </text>
            </>
          )}

          {/* Legacy-Test Zone Box (V1 or Diff) */}
          {(revision === 'v1' || revision === 'diff') && (
            <>
              <rect 
                x="870" y="680" width="240" height="200" rx="14" 
                fill="#64748b" fillOpacity="0.03" 
                stroke={revision === 'diff' ? '#f43f5e' : '#64748b'} 
                strokeOpacity={revision === 'diff' ? "0.6" : "0.3"} 
                strokeWidth={revision === 'diff' ? "2" : "1.5"} 
                strokeDasharray="6 4" 
              />
              <text x="882" y="703" fill={revision === 'diff' ? '#fb7185' : '#94a3b8'} fontSize="10" fontWeight="700">
                {revision === 'diff' ? '✖ DECOMMISSIONED: Legacy-Test' : 'ZONE: Legacy-Test'}
              </text>
            </>
          )}

          {/* Management Zone Box */}
          <rect 
            x="1170" y="240" width="220" height="230" rx="14" 
            fill="#3b82f6" fillOpacity="0.03" stroke="#3b82f6" strokeOpacity="0.25" strokeWidth="1.5" strokeDasharray="4 4" 
          />
          <text x="1182" y="263" fill="#60a5fa" fontSize="10" fontWeight="700">PAN-OS ZONE: Management (ethernet1/8)</text>

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
                                 (matchingNodeIds && (!matchingNodeIds.has(edge.source) && !matchingNodeIds.has(edge.target))) ||
                                 (hierarchyDepth !== 'all' && (edge.source.includes('host') || edge.target.includes('host') || edge.source.includes('vpn-to') || edge.target.includes('vpn-to')));

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
                    className="font-mono select-none"
                  >
                    {edge.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* 3. Layer 7 App-ID Traffic Flow Animations */}
          {showTraffic && hierarchyDepth === 'all' && (
            <>
              {/* Traffic Flow 1: Inbound Web */}
              <path 
                d="M 140 170 Q 420 180 700 300" 
                fill="none" 
                stroke="#10b981" 
                strokeWidth="2.5" 
                className="animate-traffic"
                markerEnd="url(#arrow-green)"
              />
              <text x="320" y="170" fill="#34d399" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: ssl / web-browsing [Allow-Inbound-Web]
              </text>

              {/* Traffic Flow 2: App-ID web-browsing */}
              <path 
                d="M 700 300 Q 840 230 990 270" 
                fill="none" 
                stroke="#06b6d4" 
                strokeWidth="2.5" 
                className="animate-traffic"
              />
              <text x="790" y="235" fill="#22d3ee" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: web-browsing [Allow-DMZ-to-App]
              </text>

              {/* Traffic Flow 3: App-ID postgresql */}
              <path 
                d="M 990 270 L 990 370" 
                fill="none" 
                stroke="#818cf8" 
                strokeWidth="2.5" 
                className="animate-traffic"
              />
              <text x="1005" y="325" fill="#a5b4fc" fontSize="10" fontWeight="700" className="font-mono">
                App-ID: postgresql [Allow-App-to-DB]
              </text>

              {/* Traffic Flow 4: App-ID ssl to PCI (V2 or Diff) */}
              {(revision === 'v2' || revision === 'diff') && (
                <g>
                  <path 
                    d="M 700 300 Q 820 480 990 620" 
                    fill="none" 
                    stroke="#a855f7" 
                    strokeWidth="3" 
                    className="animate-traffic"
                    markerEnd="url(#arrow-purple)"
                  />
                  <text x="790" y="475" fill="#c084fc" fontSize="10" fontWeight="700" className="font-mono">
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
                             (matchingNodeIds && !matchingNodeIds.has(node.id)) ||
                             isDepthFiltered(node);

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
                      {isDiffAdded && (
                        <span className="text-[9px] font-bold text-emerald-400 bg-emerald-950 px-1 py-0.2 rounded border border-emerald-800">
                          + ADD
                        </span>
                      )}
                      {isDiffRemoved && (
                        <span className="text-[9px] font-bold text-rose-400 bg-rose-950 px-1 py-0.2 rounded border border-rose-800">
                          - DEL
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">
                      {isFw ? 'PAN-OS 11.1 • PA-3410' :
                       isVR ? 'Virtual Router (FIB)' :
                       node.metadata?.ip || node.metadata?.cidr || (node.label?.split('\n')[1] || '')}
                    </div>

                    {node.zone && (
                      <span className="inline-block mt-1 text-[9px] font-bold px-1.5 py-0.2 rounded bg-slate-800/80 text-cyan-300 border border-slate-700 font-mono">
                        Zone: {node.zone}
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
