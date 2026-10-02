import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, CheckCircle, AlertTriangle, XCircle, Box } from 'lucide-react';
import { AgentLog, VerificationResult } from '../types';

interface SandboxTerminalProps {
  logs: AgentLog[];
  verification?: VerificationResult;
  isRunning: boolean;
}

export const SandboxTerminal: React.FC<SandboxTerminalProps> = ({ logs, verification, isRunning }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="bg-[#101624] border border-[#1e293b] rounded-2xl overflow-hidden shadow-xl flex flex-col h-full">
      {/* Terminal Title Bar */}
      <div className="px-4 py-3 bg-[#0d121c] border-b border-[#1e293b] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 mr-2">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Ephemeral Docker Sandbox Terminal
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-[#162136] text-slate-300 border border-[#23314f]">
            <Box className="w-3 h-3 text-cyan-400" />
            <span>Isolation: Strict (No Net)</span>
          </div>
        </div>
      </div>

      {/* Terminal Console Output */}
      <div className="p-4 font-mono text-xs overflow-y-auto max-h-[380px] bg-[#090c12] space-y-2 leading-relaxed">
        {logs.length === 0 ? (
          <div className="text-slate-600 italic py-8 text-center">
            &gt; Waiting for agent execution stream...
          </div>
        ) : (
          logs.map((log) => {
            let badgeBg = 'bg-slate-800 text-slate-400';
            let icon = null;

            if (log.type === 'success') {
              badgeBg = 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
              icon = <CheckCircle className="w-3 h-3 text-emerald-400 inline mr-1" />;
            } else if (log.type === 'error') {
              badgeBg = 'bg-red-500/20 text-red-400 border border-red-500/30';
              icon = <XCircle className="w-3 h-3 text-red-400 inline mr-1" />;
            } else if (log.type === 'warning') {
              badgeBg = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
              icon = <AlertTriangle className="w-3 h-3 text-amber-400 inline mr-1" />;
            } else {
              badgeBg = 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20';
            }

            return (
              <div key={log.id} className="flex items-start gap-2.5 text-slate-300">
                <span className="text-slate-600 select-none text-[11px] shrink-0">
                  {log.timestamp}
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${badgeBg}`}>
                  {log.agent}
                </span>
                <span className="text-slate-200">
                  {icon}
                  {log.message}
                </span>
              </div>
            );
          })
        )}

        {/* Verification Report Card if present */}
        {verification && (
          <div className={`mt-4 p-3 rounded-xl border text-xs ${
            verification.passed 
              ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
              : 'bg-red-950/20 border-red-500/40 text-red-300'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold uppercase tracking-wider flex items-center gap-1.5">
                {verification.passed ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>Sandbox Verification: {verification.passed ? 'PASSED' : 'FAILED'}</span>
              </span>
              <span className="text-[11px] text-slate-400">Duration: {verification.durationSeconds}s</span>
            </div>
            <pre className="p-2 rounded bg-black/50 text-[11px] font-mono whitespace-pre-wrap overflow-x-auto text-slate-300">
              {verification.testOutput}
            </pre>
          </div>
        )}

        {isRunning && (
          <div className="flex items-center gap-2 text-cyan-400 py-1">
            <span className="animate-pulse">&gt;</span>
            <span className="text-xs">Agents reasoning &amp; verifying patch...</span>
          </div>
        )}

        <div ref={bottomRef} />
      </div>
    </div>
  );
};
