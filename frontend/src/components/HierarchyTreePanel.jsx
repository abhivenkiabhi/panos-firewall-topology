import React, { useState, useMemo } from 'react';
import { 
  FolderTree, 
  ChevronRight, 
  ChevronDown, 
  Flame, 
  Route, 
  Globe, 
  Database, 
  CreditCard, 
  Key, 
  Server, 
  Shield, 
  Layers, 
  X, 
  Search
} from 'lucide-react';

export default function HierarchyTreePanel({ 
  isOpen, 
  onClose, 
  topologyData, 
  selectedNode, 
  onSelectNode,
  revision 
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [collapsedZones, setCollapsedZones] = useState({});

  const toggleZone = (zoneName) => {
    setCollapsedZones(prev => ({
      ...prev,
      [zoneName]: !prev[zoneName]
    }));
  };

  // Build the hierarchical tree structure from topologyData
  const hierarchyTree = useMemo(() => {
    if (!topologyData?.nodes) return null;

    // Filter by revision
    const activeNodes = topologyData.nodes.filter(node => {
      if (revision === 'v2' && node.id?.includes('Legacy')) return false;
      if (revision === 'v1' && node.id?.includes('PCI')) return false;
      return true;
    });

    const fwNode = activeNodes.find(n => n.type === 'firewall');
    const vrNode = activeNodes.find(n => n.type === 'virtual_router');

    // Group remaining nodes by zone
    const zonesMap = {
      'Untrust': {
        name: 'Untrust',
        tier: 'Tier 1: External / Perimeter',
        interface: 'ethernet1/1',
        trustLevel: 'UNTRUSTED',
        badgeColor: 'rose',
        subnets: [],
        endpoints: []
      },
      'VPN-SiteToSite': {
        name: 'VPN-SiteToSite',
        tier: 'Tier 1: Encrypted WAN Tunnels',
        interface: 'tunnel.1 & tunnel.2',
        trustLevel: 'SITE-TO-SITE VPN',
        badgeColor: 'sky',
        subnets: [],
        endpoints: []
      },
      'DMZ': {
        name: 'DMZ',
        tier: 'Tier 3: Inbound Public Services',
        interface: 'ethernet1/2',
        trustLevel: 'SEMI-TRUSTED',
        badgeColor: 'amber',
        subnets: [],
        endpoints: []
      },
      'Trust-Internal': {
        name: 'Trust-Internal',
        tier: 'Tier 4: Enterprise Internal Network',
        interface: 'ethernet1/3',
        trustLevel: 'HIGH TRUST',
        badgeColor: 'emerald',
        subnets: [],
        endpoints: []
      },
      'PCI-Cardholder': {
        name: 'PCI-Cardholder',
        tier: 'Tier 4: Payment Card Isolation (CR-4910)',
        interface: 'ethernet1/5',
        trustLevel: 'RESTRICTED COMPLIANCE',
        badgeColor: 'purple',
        subnets: [],
        endpoints: []
      },
      'Management': {
        name: 'Management',
        tier: 'Tier 5: Out-of-band Admin Plane',
        interface: 'ethernet1/8',
        trustLevel: 'RESTRICTED OOB',
        badgeColor: 'blue',
        subnets: [],
        endpoints: []
      }
    };

    activeNodes.forEach(node => {
      if (node.type === 'firewall' || node.type === 'virtual_router') return;

      const zone = node.zone || (node.id?.includes('Untrust') ? 'Untrust' : 
                                 node.id?.includes('VPN') ? 'VPN-SiteToSite' :
                                 node.id?.includes('DMZ') ? 'DMZ' :
                                 node.id?.includes('Trust') ? 'Trust-Internal' :
                                 node.id?.includes('PCI') ? 'PCI-Cardholder' :
                                 node.id?.includes('Management') ? 'Management' : 'Untrust');

      if (!zonesMap[zone]) {
        zonesMap[zone] = {
          name: zone,
          tier: 'Custom Zone',
          interface: 'Custom',
          trustLevel: 'STANDARD',
          badgeColor: 'slate',
          subnets: [],
          endpoints: []
        };
      }

      if (node.type === 'subnet') {
        zonesMap[zone].subnets.push(node);
      } else {
        zonesMap[zone].endpoints.push(node);
      }
    });

    return {
      firewall: fwNode,
      virtualRouter: vrNode,
      zones: Object.values(zonesMap).filter(z => z.subnets.length > 0 || z.endpoints.length > 0)
    };
  }, [topologyData, revision]);

  if (!isOpen) return null;

  const matchesSearch = (text) => {
    if (!searchTerm.trim()) return true;
    return text?.toLowerCase().includes(searchTerm.toLowerCase());
  };

  const getNodeIcon = (node) => {
    const id = node?.id || '';
    if (id.includes('PA-NGFW')) return <Flame className="w-4 h-4 text-[#fa582d]" />;
    if (id.includes('vr-default')) return <Route className="w-4 h-4 text-amber-400" />;
    if (id.includes('vpn') || id.includes('aws') || id.includes('branch')) return <Globe className="w-4 h-4 text-sky-400" />;
    if (id.includes('internet')) return <Globe className="w-4 h-4 text-rose-400" />;
    if (id.includes('DB') || id.includes('50')) return <Database className="w-4 h-4 text-emerald-400" />;
    if (id.includes('PCI') || id.includes('PAYMENT') || id.includes('25')) return <CreditCard className="w-4 h-4 text-purple-400" />;
    if (id.includes('BASTION') || id.includes('Management')) return <Key className="w-4 h-4 text-blue-400" />;
    if (node?.type === 'subnet') return <Layers className="w-3.5 h-3.5 text-slate-400" />;
    return <Server className="w-4 h-4 text-slate-300" />;
  };

  return (
    <aside className="fixed inset-y-0 left-0 w-96 bg-[#0b0f19] border-r border-slate-800 z-50 flex flex-col shadow-2xl backdrop-blur-xl animate-in slide-in-from-left duration-200">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-[#fa582d]/15 border border-[#fa582d]/30 text-[#fa582d]">
            <FolderTree className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-extrabold text-sm text-white flex items-center space-x-2">
              <span>PAN-OS Hierarchy</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                5-Tier
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Containment model & security boundaries
            </p>
          </div>
        </div>
        <button 
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Filter / Search Bar */}
      <div className="p-3 border-b border-slate-800/80 bg-slate-950/40">
        <div className="flex items-center space-x-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-xl">
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <input 
            type="text" 
            placeholder="Filter hierarchy by name, IP, or zone..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none w-full font-mono"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="text-slate-500 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Tree Content */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {hierarchyTree && (
          <div className="space-y-2">
            {/* 1. Appliance Level */}
            {hierarchyTree.firewall && (
              <div 
                onClick={() => onSelectNode(hierarchyTree.firewall)}
                className={`p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                  selectedNode?.id === hierarchyTree.firewall.id 
                    ? 'bg-[#fa582d]/20 border-[#fa582d] shadow-lg shadow-[#fa582d]/20' 
                    : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <div className="p-1.5 rounded-lg bg-[#fa582d]/20 text-[#fa582d]">
                    <Flame className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white flex items-center space-x-1.5">
                      <span>PA-NGFW-CORE-01</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#fa582d]/20 text-[#fa582d]">PA-3410</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      Tier 2 Chassis • PAN-OS 11.1
                    </div>
                  </div>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 font-bold bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800">
                  ACTIVE
                </span>
              </div>
            )}

            {/* 2. Virtual Router Level */}
            {hierarchyTree.virtualRouter && (
              <div className="pl-4 border-l-2 border-slate-800 space-y-2">
                <div 
                  onClick={() => onSelectNode(hierarchyTree.virtualRouter)}
                  className={`p-2 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                    selectedNode?.id === hierarchyTree.virtualRouter.id 
                      ? 'bg-amber-500/20 border-amber-500 shadow-md shadow-amber-500/20' 
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Route className="w-4 h-4 text-amber-400" />
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        Virtual Router: <span className="font-mono font-bold text-amber-300">default</span>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        FIB / RIB Routing Domain
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    6 Routes
                  </span>
                </div>

                {/* 3. Security Zones Level */}
                <div className="pl-3 border-l-2 border-slate-800/80 space-y-2 pt-1">
                  {hierarchyTree.zones.map((zone) => {
                    const isCollapsed = collapsedZones[zone.name];
                    const allZoneItems = [...zone.subnets, ...zone.endpoints];
                    const hasMatch = allZoneItems.some(item => 
                      matchesSearch(item.label) || matchesSearch(item.metadata?.ip) || matchesSearch(zone.name)
                    );

                    if (searchTerm && !hasMatch) return null;

                    return (
                      <div key={zone.name} className="rounded-xl bg-slate-900/50 border border-slate-800/90 overflow-hidden">
                        {/* Zone Header */}
                        <div 
                          onClick={() => toggleZone(zone.name)}
                          className="p-2.5 flex items-center justify-between cursor-pointer hover:bg-slate-800/60 transition-colors"
                        >
                          <div className="flex items-center space-x-2 min-w-0">
                            {isCollapsed ? (
                              <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                            )}
                            <Shield className={`w-3.5 h-3.5 text-${zone.badgeColor}-400`} />
                            <div className="truncate">
                              <span className="text-xs font-bold text-white block truncate">
                                Zone: {zone.name}
                              </span>
                              <span className="text-[10px] text-slate-400 font-mono block truncate">
                                {zone.interface} • {zone.trustLevel}
                              </span>
                            </div>
                          </div>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 ml-2 shrink-0">
                            {zone.endpoints.length} nodes
                          </span>
                        </div>

                        {/* Zone Children (Subnets & Endpoints) */}
                        {!isCollapsed && (
                          <div className="px-2.5 pb-2.5 pt-1 space-y-1.5 border-t border-slate-800/60 bg-slate-950/30">
                            {/* Subnets */}
                            {zone.subnets.map((sub) => (
                              <div
                                key={sub.id}
                                onClick={() => onSelectNode(sub)}
                                className={`p-1.5 rounded-lg border text-xs flex items-center justify-between cursor-pointer transition-all ${
                                  selectedNode?.id === sub.id 
                                    ? 'bg-indigo-950 border-indigo-500 text-white shadow' 
                                    : 'bg-slate-900/80 border-slate-800/80 text-slate-300 hover:border-slate-700'
                                }`}
                              >
                                <div className="flex items-center space-x-2">
                                  <Layers className="w-3 h-3 text-indigo-400" />
                                  <span className="font-mono text-[11px] font-semibold">
                                    {sub.metadata?.cidr || sub.label?.split('\n')[0]}
                                  </span>
                                </div>
                                <span className="text-[9px] text-slate-500 uppercase font-mono">
                                  L3 Subnet
                                </span>
                              </div>
                            ))}

                            {/* Endpoints / Workloads */}
                            {zone.endpoints.map((ep) => {
                              const isSelected = selectedNode?.id === ep.id;
                              return (
                                <div
                                  key={ep.id}
                                  onClick={() => onSelectNode(ep)}
                                  className={`p-2 rounded-lg border text-xs flex items-center justify-between cursor-pointer transition-all ${
                                    isSelected 
                                      ? 'bg-amber-500/20 border-amber-500 text-amber-200 shadow-md shadow-amber-500/10' 
                                      : 'bg-slate-900/90 border-slate-800/90 text-slate-300 hover:border-slate-700 hover:bg-slate-800/70'
                                  }`}
                                >
                                  <div className="flex items-center space-x-2 min-w-0">
                                    {getNodeIcon(ep)}
                                    <div className="truncate">
                                      <div className="font-medium text-slate-100 truncate text-[11px]">
                                        {ep.label?.split('\n')[0]}
                                      </div>
                                      <div className="text-[10px] font-mono text-cyan-400">
                                        {ep.metadata?.ip || ep.metadata?.cidr || 'Gateway / Peer'}
                                      </div>
                                    </div>
                                  </div>

                                  {ep.diff_status && (
                                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.2 rounded ${
                                      ep.diff_status === 'added' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                                    }`}>
                                      {ep.diff_status}
                                    </span>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-slate-800 bg-slate-900/60 text-[11px] text-slate-400 flex items-center justify-between">
        <span>Click any node to zoom & isolate</span>
        <span className="font-mono text-slate-500">Strata 11.1</span>
      </div>
    </aside>
  );
}
