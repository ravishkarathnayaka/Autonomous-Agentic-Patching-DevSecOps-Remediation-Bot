import React from 'react';
import { Search, Code2, FlaskConical, GitPullRequest, ArrowRight, RefreshCw, CheckCircle2, AlertCircle } from 'lucide-react';
import { RemediationStatus } from '../types';

interface AgentPipelineProps {
  status: RemediationStatus;
  retryCount: number;
}

export const AgentPipeline: React.FC<AgentPipelineProps> = ({ status, retryCount }) => {
  const steps = [
    {
      id: 'triage',
      name: 'Triage Agent',
      role: 'AST & Root Cause Analysis',
      icon: Search,
      isActive: status === 'TRIAGING',
      isCompleted: ['PATCHING', 'VERIFYING', 'RETRY_NEEDED', 'VERIFIED', 'PR_READY'].includes(status)
    },
    {
      id: 'patch',
      name: 'Patch Agent',
      role: 'Surgical Diff Synthesis',
      icon: Code2,
      isActive: status === 'PATCHING',
      isCompleted: ['VERIFYING', 'RETRY_NEEDED', 'VERIFIED', 'PR_READY'].includes(status)
    },
    {
      id: 'verifier',
      name: 'Verifier Agent',
      role: 'Ephemeral Docker Sandbox',
      icon: FlaskConical,
      isActive: status === 'VERIFYING',
      isRetry: status === 'RETRY_NEEDED',
      isCompleted: ['VERIFIED', 'PR_READY'].includes(status)
    },
    {
      id: 'pr',
      name: 'PR Agent',
      role: 'Threat Mitigation & Branching',
      icon: GitPullRequest,
      isActive: status === 'PR_READY',
      isCompleted: status === 'PR_READY'
    }
  ];

  return (
    <div className="bg-[#101624] border border-[#1e293b] rounded-2xl p-4 lg:p-6 shadow-xl relative overflow-hidden">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <span>Multi-Agent State Orchestrator</span>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
          </h2>
          <p className="text-xs text-slate-400">Autonomous workflow transitions with self-healing feedback loop</p>
        </div>

        {retryCount > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-medium">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>Self-Healing Iteration #{retryCount + 1} / 3</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isCurrent = step.isActive;
          const isDone = step.isCompleted;
          const isFailed = step.isRetry;

          return (
            <div key={step.id} className="relative flex flex-col items-center text-center">
              {/* Connector line for desktop */}
              {idx < steps.length - 1 && (
                <div className="hidden md:block absolute top-7 left-1/2 w-full h-[2px] bg-[#1e293b] z-0">
                  <div
                    className={`h-full transition-all duration-500 ${
                      isDone ? 'bg-gradient-to-r from-emerald-500 to-cyan-500' : 'bg-transparent'
                    }`}
                  />
                </div>
              )}

              {/* Node Avatar */}
              <div
                className={`relative z-10 w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-300 ${
                  isCurrent
                    ? 'bg-cyan-500/20 border-2 border-cyan-400 text-cyan-300 shadow-lg shadow-cyan-500/30 scale-105 animate-pulse'
                    : isDone
                    ? 'bg-emerald-500/20 border-2 border-emerald-400 text-emerald-300 shadow-md shadow-emerald-500/20'
                    : isFailed
                    ? 'bg-amber-500/20 border-2 border-amber-400 text-amber-300'
                    : 'bg-[#151c2d] border border-[#22314a] text-slate-500'
                }`}
              >
                <Icon className="w-6 h-6" />
                {isDone && (
                  <div className="absolute -top-1 -right-1 bg-emerald-500 text-black rounded-full p-0.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  </div>
                )}
                {isFailed && (
                  <div className="absolute -top-1 -right-1 bg-amber-500 text-black rounded-full p-0.5">
                    <AlertCircle className="w-3.5 h-3.5" />
                  </div>
                )}
              </div>

              {/* Node Labels */}
              <div className="mt-3">
                <p className={`text-sm font-semibold tracking-tight ${isCurrent ? 'text-cyan-300' : isDone ? 'text-emerald-300' : 'text-slate-300'}`}>
                  {step.name}
                </p>
                <p className="text-xs text-slate-500 mt-0.5 max-w-[150px]">
                  {step.role}
                </p>
              </div>

              {/* Status Badge */}
              <div className="mt-2">
                {isCurrent && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    Executing...
                  </span>
                )}
                {isDone && !isCurrent && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Passed
                  </span>
                )}
                {isFailed && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    Retrying...
                  </span>
                )}
                {!isCurrent && !isDone && !isFailed && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-800 text-slate-500">
                    Idle
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
