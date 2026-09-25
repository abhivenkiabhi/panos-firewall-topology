import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import DiffSummaryBanner from './components/DiffSummaryBanner';
import TopologyCanvas from './components/TopologyCanvas';
import InspectorDrawer from './components/InspectorDrawer';
import ReachabilitySimulator from './components/ReachabilitySimulator';
import ChatAssistantDrawer from './components/ChatAssistantDrawer';
import LogStreamViewer from './components/LogStreamViewer';

export default function App() {
  const [revision, setRevision] = useState('v2'); // 'v1' | 'v2' | 'diff'
  const [showTraffic, setShowTraffic] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [simulationResult, setSimulationResult] = useState(null);
  
  // Modals & Drawers
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [isLogsOpen, setIsLogsOpen] = useState(false);

  // Data states
  const [topologyData, setTopologyData] = useState(null);
  const [configData, setConfigData] = useState(null);
  const [logData, setLogData] = useState(null);
  const [diffStats, setDiffStats] = useState(null);
  const [diffSummaryItems, setDiffSummaryItems] = useState([]);
  const [prefilledSimulatorSrc, setPrefilledSimulatorSrc] = useState('');

  // Fetch topology when revision changes
  useEffect(() => {
    const fetchTopology = async () => {
      try {
        if (revision === 'diff') {
          const res = await fetch('/api/topology/diff');
          const data = await res.json();
          setTopologyData({
            nodes: data.nodes,
            edges: data.edges,
            zones: data.zones
          });
          setDiffStats(data.stats);
          setDiffSummaryItems(data.summary_items || []);
        } else {
          const res = await fetch(`/api/topology?revision=${revision}`);
          const data = await res.json();
          setTopologyData(data);
        }
      } catch (err) {
        console.error('Failed to fetch topology:', err);
      }
    };

    fetchTopology();
  }, [revision]);

  // Fetch config and logs once on mount
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [cfgRes, logRes] = await Promise.all([
          fetch(`/api/config?revision=${revision === 'diff' ? 'v2' : revision}`),
          fetch('/api/logs?limit=100')
        ]);
        const cfg = await cfgRes.json();
        const logs = await logRes.json();
        setConfigData(cfg);
        setLogData(logs);
      } catch (err) {
        console.error('Failed to load initial data:', err);
      }
    };

    fetchData();
  }, [revision]);

  const handleSimulateWithNode = (ip) => {
    setPrefilledSimulatorSrc(ip);
    setIsSimulatorOpen(true);
  };

  const handleHighlightNodes = (nodeIds) => {
    if (topologyData?.nodes && nodeIds?.length > 0) {
      const match = topologyData.nodes.find(n => nodeIds.includes(n.id));
      if (match) setSelectedNode(match);
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#090d16] text-slate-100">
      {/* Top Navigation */}
      <Header
        revision={revision}
        setRevision={setRevision}
        showTraffic={showTraffic}
        setShowTraffic={setShowTraffic}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenChat={() => setIsChatOpen(true)}
        onOpenLogs={() => setIsLogsOpen(true)}
      />

      {/* Diff Banner when in Diff Mode */}
      {revision === 'diff' && (
        <DiffSummaryBanner 
          stats={diffStats} 
          summaryItems={diffSummaryItems}
          onSelectEntity={(entity) => console.log(entity)}
        />
      )}

      {/* Main Interactive Canvas */}
      <main className="flex-1 relative overflow-hidden">
        <TopologyCanvas
          topologyData={topologyData}
          revision={revision}
          showTraffic={showTraffic}
          selectedNode={selectedNode}
          onSelectNode={(node) => setSelectedNode(node)}
          simulationResult={simulationResult}
          onClearSimulation={() => setSimulationResult(null)}
        />
      </main>

      {/* Slide-out Inspector Drawer */}
      {selectedNode && (
        <InspectorDrawer
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
          configData={configData}
          logData={logData}
          onSimulateWithNode={handleSimulateWithNode}
        />
      )}

      {/* Reachability Simulator Modal */}
      <ReachabilitySimulator
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        revision={revision}
        prefilledSrc={prefilledSimulatorSrc}
        onSimulateComplete={(result) => {
          setSimulationResult(result);
          setIsSimulatorOpen(false);
        }}
      />

      {/* Customer AI Assistant Drawer */}
      <ChatAssistantDrawer
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        onHighlightNodes={handleHighlightNodes}
      />

      {/* Syslog Stream Viewer Modal */}
      <LogStreamViewer
        isOpen={isLogsOpen}
        onClose={() => setIsLogsOpen(false)}
        logData={logData}
      />
    </div>
  );
}
