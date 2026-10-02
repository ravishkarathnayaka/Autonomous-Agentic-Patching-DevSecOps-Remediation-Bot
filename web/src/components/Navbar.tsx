import React from 'react';
import { Shield, GitPullRequest, Terminal, Github, ExternalLink } from 'lucide-react';

interface NavbarProps {
  onOpenPr: () => void;
  hasPr: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ onOpenPr, hasPr }) => {
  return (
    <header className="border-b border-[#1f293d] bg-[#0c101a]/80 backdrop-blur-md sticky top-0 z-50 px-4 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-5 h-5 animate-pulse-slow" />
            <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-[#0a0d14]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-tight text-white text-base lg:text-lg">
                Autonomous DevSecOps Bot
              </span>
              <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Agentic 2.0
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Multi-Agent SAST/SCA Triage • Surgical Patching • Ephemeral Sandbox Verification
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          {hasPr && (
            <button
              onClick={onOpenPr}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/25 transition-all text-xs font-semibold shadow-sm shadow-emerald-500/20 animate-pulse"
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              <span>View Generated PR</span>
            </button>
          )}

          <a
            href="https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#141c2e] hover:bg-[#1a253d] border border-[#23314f] text-slate-300 hover:text-white transition-all text-xs font-medium"
          >
            <Github className="w-3.5 h-3.5" />
            <span className="hidden md:inline">GitHub Repository</span>
            <ExternalLink className="w-3 h-3 text-slate-500" />
          </a>
        </div>
      </div>
    </header>
  );
};
