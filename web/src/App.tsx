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
import { Code2, Terminal, Shield, Sparkles, ExternalLink, Zap } from 'lucide-react';

export function App() {
  const [selectedScenario, setSelectedScenario] = useState<PresetScenario>(PRESET_SCENARIOS[0]);
  const [simulateRetry, setSimulateRetry] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [result, setResult] = useState<RemediationResult | null>(null);
  const [activeTab, setActiveTab] = useState<'diff' | 'terminal' | 'both'>('both');
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
          particleCount: 80,
          spread: 60,
          origin: { y: 0.6 }
        });
      }
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      <Navbar onOpenPr={() => setIsPrModalOpen(true)} hasPr={Boolean(result?.prBody)} />

      <main className="flex-1 max-w-7xl mx-auto w-full p-4 lg:p-8 space-y-6">
        {/* Hero Banner / Status */}
        <div className="bg-gradient-to-r from-cyan-950/30 via-[#101826] to-emerald-950/30 border border-[#1f2b42] rounded-2xl p-5 lg:p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wide uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 flex items-center gap-1.5">
                <Sparkles className="w-3 h-3" />
                Live Agentic Sandbox
              </span>
              <span className="text-xs text-slate-400">Zero Server Cost • Local AI Support</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white">
              Autonomous Agentic Patching &amp; DevSecOps Remediation
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Ingest SAST/SCA alerts, extract AST context, synthesize surgical security patches, and verify regressions inside an ephemeral Docker sandbox container with closed-loop self-healing.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start md:self-auto">
            {result?.prBody && (
              <button
                onClick={() => setIsPrModalOpen(true)}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-black font-bold text-xs uppercase tracking-wider shadow-lg shadow-emerald-500/20 transition-all flex items-center gap-2"
              >
                <span>View Generated PR</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Multi-Agent Visual State Graph */}
        <AgentPipeline
          status={result?.status || 'IDLE'}
          retryCount={result?.retryCount || 0}
        />

        {/* Vulnerability Selector & Controls */}
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

        {/* View Toggle Bar */}
        <div className="flex items-center justify-between pt-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('both')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'both'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              Split View (Diff &amp; Sandbox)
            </button>
            <button
              onClick={() => setActiveTab('diff')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === 'diff'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Patch Diff</span>
            </button>
            <button
              onClick={() => setActiveTab('terminal')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === 'terminal'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e293b]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Sandbox Logs</span>
            </button>
          </div>
        </div>

        {/* Main Work Area: Diff Viewer & Terminal */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[460px]">
          {(activeTab === 'both' || activeTab === 'diff') && (
            <div className={activeTab === 'diff' ? 'lg:col-span-2' : ''}>
              <DiffViewer
                diffText={result?.patchDiff}
                explanation={result?.patchExplanation}
                filePath={selectedScenario.finding.filePath}
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

      {/* PR Modal */}
      <PullRequestModal
        isOpen={isPrModalOpen}
        onClose={() => setIsPrModalOpen(false)}
        result={result || undefined}
      />

      {/* Footer */}
      <footer className="border-t border-[#1a2336] bg-[#0c101a] py-6 px-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
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
