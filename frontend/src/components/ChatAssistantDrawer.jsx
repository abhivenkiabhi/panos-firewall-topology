import React, { useState, useRef, useEffect } from 'react';
import { X, Send, Bot, User, Flame, CheckCircle2, ShieldAlert } from 'lucide-react';

export default function ChatAssistantDrawer({ 
  isOpen, 
  onClose, 
  onHighlightNodes 
}) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Hello! I am your **Palo Alto Networks Strata & PAN-OS Assistant**. Ask me anything about our network topology, App-ID policies, commit diffs (CR-4910), or dropped sessions in PAN-OS logs.",
      category: 'welcome'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const quickPrompts = [
    "What changed in PAN-OS config for CR-4910?",
    "Can DMZ Web reach Payment GW with App-ID ssl?",
    "Why was traffic from 198.51.100.22 dropped?",
    "Can DMZ Web talk directly to Database on postgresql?",
    "What security zones and virtual routers are configured?"
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  if (!isOpen) return null;

  const handleSend = async (textToSend = input) => {
    const q = textToSend.trim();
    if (!q || loading) return;

    const userMsg = { role: 'user', content: q };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q })
      });
      const data = await res.json();
      
      const assistantMsg = {
        role: 'assistant',
        content: data.answer,
        category: data.category,
        related_nodes: data.related_nodes,
        simulation: data.simulation
      };
      setMessages(prev => [...prev, assistantMsg]);

      if (data.related_nodes && onHighlightNodes) {
        onHighlightNodes(data.related_nodes);
      }
    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "Sorry, I encountered an error querying the PAN-OS topology backend.",
        category: 'error'
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <aside className="fixed top-16 right-0 w-[450px] h-[calc(100vh-64px)] bg-[#0d1322] border-l border-slate-800 shadow-2xl flex flex-col z-40 backdrop-blur overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 bg-[#11192d] border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-gradient-to-tr from-[#e03a14] via-[#fa582d] to-amber-500 text-white shadow-md shadow-[#fa582d]/25">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <h3 className="text-sm font-bold text-white">PAN-OS Strata Assistant</h3>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 font-medium">PAN-OS 11.1</span>
            </div>
            <p className="text-[11px] text-slate-400">Context: PA-NGFW-CORE-01 (PA-3410) & Live Logs</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-3 py-2 bg-slate-900/60 border-b border-slate-800/80 overflow-x-auto whitespace-nowrap flex space-x-1.5 scrollbar-thin">
        {quickPrompts.map((qp, i) => (
          <button
            key={i}
            onClick={() => handleSend(qp)}
            className="text-[11px] px-2.5 py-1 rounded-full bg-slate-800 hover:bg-[#fa582d]/20 hover:text-[#fa582d] border border-slate-700/60 text-slate-300 transition-all flex-shrink-0"
          >
            {qp}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, idx) => (
          <div 
            key={idx} 
            className={`flex items-start space-x-2.5 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {msg.role === 'assistant' && (
              <div className="w-7 h-7 rounded-lg bg-[#fa582d]/20 border border-[#fa582d]/40 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Flame className="w-4 h-4 text-[#fa582d]" />
              </div>
            )}

            <div className={`rounded-2xl p-3 text-xs leading-relaxed max-w-[85%] ${
              msg.role === 'user' 
                ? 'bg-[#fa582d] text-white shadow-md' 
                : 'bg-slate-900/90 border border-slate-800 text-slate-200 shadow-sm'
            }`}>
              <div className="whitespace-pre-wrap">
                {msg.content}
              </div>

              {msg.simulation && (
                <div className={`mt-2 p-2.5 rounded-xl border text-[11px] ${
                  msg.simulation.action === 'ALLOW' 
                    ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-200' 
                    : 'bg-rose-950/40 border-rose-700/60 text-rose-200'
                }`}>
                  <div className="font-bold uppercase tracking-wider mb-1 flex items-center space-x-1">
                    {msg.simulation.action === 'ALLOW' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                    <span>PAN-OS Decision: {msg.simulation.action}</span>
                  </div>
                  <div>Rule: <strong>"{msg.simulation.rule_name}"</strong> (App-ID: <code>{msg.simulation.app_id}</code>)</div>
                </div>
              )}
            </div>

            {msg.role === 'user' && (
              <div className="w-7 h-7 rounded-lg bg-slate-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                <User className="w-4 h-4 text-slate-300" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center space-x-2 text-xs text-slate-400 italic pl-10">
            <span className="w-2 h-2 rounded-full bg-[#fa582d] animate-ping"></span>
            <span>Querying PAN-OS rulebase & logs...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <div className="p-3 bg-slate-900 border-t border-slate-800">
        <form 
          onSubmit={(e) => { e.preventDefault(); handleSend(); }}
          className="flex items-center space-x-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask PAN-OS assistant (e.g. Can DMZ reach DB?)..."
            className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#fa582d]"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="p-2 rounded-xl bg-[#fa582d] hover:brightness-110 disabled:opacity-50 text-white shadow-md shadow-[#fa582d]/30 transition-all"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </aside>
  );
}
