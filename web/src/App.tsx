import React, { useState } from 'react';
import confetti from 'canvas-confetti';
import { Navbar } from './components/Navbar';
import { AgentPipeline } from './components/AgentPipeline';
import { VulnerabilitySelector } from './components/VulnerabilitySelector';
import { DiffViewer } from './components/DiffViewer';
import { SandboxTerminal } from './components/SandboxTerminal';
import { PullRequestModal } from './components/PullRequestModal';
import { PRESET_SCENARIOS, PresetScenario } from './data/scenarios';
import { RemediationResult } from './types';
import { runRemediationPipeline } from './engine/agentRunner';
import { Code2, Terminal, Shield, Sparkles, ExternalLink, Zap, LayoutGrid, CheckCircle2 } from 'lucide-react';

export function App() {
  const [selectedScenario, setSelectedScenario] = useState<PresetScenario>(PRESET_SCENARIOS[0]);
  const [simulateRetry, setSimulateRetry] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [result, setResult] = useState<RemediationResult | null>(null);
  const [activeTab, setActiveTab] = useState<'both' | 'diff' | 'terminal'>('both');
  const [isPrModalOpen, setIsPrModalOpen] = useState<boolean>(false);

  const handleStart = async () => {
    setIsRunning(true);
    try {
      const finalResult = await runRemediationPipeline(
        selectedScenario,
        simulateRetry,
        (updated) => setResult({ ...updated })
      );

      if (finalResult.status === 'PR_READY') {
        confetti({
          particleCount: 90,
          spread: 70,
          origin: { y: 0.6 }
        });
      }
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      {/* Top Navigation */}
      <Navbar onOpenPr={() => setIsPrModalOpen(true)} hasPr={Boolean(result?.prBody)} />

      <main className="flex-1 max-w-7xl mx-auto w-full p-3 sm:p-5 lg:p-6 space-y-4 sm:space-y-5">
        {/* Banner with Status & PR Trigger */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0d131f] border border-[#1e2a3e] rounded-xl px-4 py-3 shadow-md">
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wide uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 flex items-center gap-1.5 shrink-0">
              <Sparkles className="w-3 h-3" />
              Live Interactive Sandbox
            </span>
            <span className="text-xs text-slate-400">
              Zero Server Cost • Ephemeral Docker Execution • Multi-Agent Closed Loop
            </span>
          </div>

          {result?.prBody && (
            <button
              onClick={() => setIsPrModalOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-teal-400 hover:from-emerald-400 hover:to-teal-300 text-black font-bold text-xs uppercase tracking-wider shadow-lg shadow-emerald-500/20 transition-all flex items-center gap-1.5 cursor-pointer shrink-0 animate-bounce"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>View Generated PR Description</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* 1. VULNERABILITY FINDING SELECTOR (PROMINENT AT TOP!) */}
        <VulnerabilitySelector
          selectedScenario={selectedScenario}
          onSelect={(sc) => {
            setSelectedScenario(sc);
            setResult(null);
          }}
          isRunning={isRunning}
          onStart={handleStart}
          simulateRetry={simulateRetry}
          onToggleRetry={setSimulateRetry}
        />

        {/* 2. MULTI-AGENT STATE GRAPH */}
        <AgentPipeline
          status={result?.status || 'IDLE'}
          retryCount={result?.retryCount || 0}
        />

        {/* 3. WORKSPACE VIEW TOGGLE BAR */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 mr-1">
              <LayoutGrid className="w-3.5 h-3.5 text-cyan-400" />
              <span>Workspace View:</span>
            </span>

            <button
              onClick={() => setActiveTab('both')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === 'both'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              Split View (Code &amp; Terminal)
            </button>
            <button
              onClick={() => setActiveTab('diff')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'diff'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>{result?.patchDiff ? 'Unified Patch Diff' : 'Vulnerable Code'}</span>
            </button>
            <button
              onClick={() => setActiveTab('terminal')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'terminal'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Docker Sandbox Terminal</span>
            </button>
          </div>

          <div className="text-[11px] text-slate-400 flex items-center gap-2">
            <span>Target: <span className="font-mono text-cyan-400">{selectedScenario.finding.filePath}</span></span>
          </div>
        </div>

        {/* 4. MAIN WORKSPACE: DUAL PANES */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-[420px]">
          {(activeTab === 'both' || activeTab === 'diff') && (
            <div className={activeTab === 'diff' ? 'lg:col-span-2' : ''}>
              <DiffViewer
                diffText={result?.patchDiff}
                explanation={result?.patchExplanation}
                filePath={selectedScenario.finding.filePath}
                initialSourceCode={selectedScenario.initialSourceCode}
                vulnerableCode={selectedScenario.finding.vulnerableCode}
                findingTitle={selectedScenario.finding.title}
                cwe={selectedScenario.finding.cwe}
              />
            </div>
          )}

          {(activeTab === 'both' || activeTab === 'terminal') && (
            <div className={activeTab === 'terminal' ? 'lg:col-span-2' : ''}>
              <SandboxTerminal
                logs={result?.logs || []}
                verification={result?.verification}
                isRunning={isRunning}
              />
            </div>
          )}
        </div>
      </main>

      {/* Pull Request Modal */}
      <PullRequestModal
        isOpen={isPrModalOpen}
        onClose={() => setIsPrModalOpen(false)}
        result={result || undefined}
      />

      {/* Footer */}
      <footer className="border-t border-[#1a2336] bg-[#0c101a] py-4 px-4 text-center text-xs text-slate-500 mt-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <p>
            Autonomous Agentic Patching &amp; DevSecOps Remediation Bot • Open Source (MIT)
          </p>
          <a
            href="https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot"
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 hover:underline flex items-center gap-1"
          >
            <span>View Source on GitHub</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </footer>
    </div>
  );
}
export default App;
