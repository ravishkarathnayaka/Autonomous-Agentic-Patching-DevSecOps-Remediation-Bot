import React, { useState } from 'react';
import { GitPullRequest, X, Copy, Check, Download, GitBranch, GitCommit, ShieldCheck, FileJson } from 'lucide-react';
import { RemediationResult } from '../types';

interface PullRequestModalProps {
  isOpen: boolean;
  onClose: () => void;
  result?: RemediationResult;
}

export const PullRequestModal: React.FC<PullRequestModalProps> = ({ isOpen, onClose, result }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !result || !result.prBody) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(result.prBody || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([result.prBody || ''], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `PR-${result.finding.id}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadSarif = () => {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: {
          driver: {
            name: "Autonomous-DevSecOps-Bot",
            version: "1.0.0",
            rules: [{
              id: result.finding.ruleId,
              name: result.finding.title,
              shortDescription: { text: result.finding.title },
              fullDescription: { text: result.finding.description }
            }]
          }
        },
        results: [{
          ruleId: result.finding.ruleId,
          level: "error",
          message: { text: result.finding.description },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: result.finding.filePath },
              region: { startLine: result.finding.startLine, endLine: result.finding.endLine }
            }
          }]
        }]
      }]
    };
    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${result.finding.id}.sarif`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f1422] border border-[#23314f] rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-[#1f293d] bg-[#0c101a] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <GitPullRequest className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                  Automated Pull Request Generated
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">
                  Open
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-bold text-white mt-0.5 line-clamp-1">
                {result.prTitle}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Git Branch & Commit Meta */}
        <div className="px-5 py-3 bg-[#131b2c] border-b border-[#1f293d] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1.5 text-slate-300">
              <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
              <span className="font-mono text-cyan-300 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/50">
                {result.prBranch}
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400">
              <GitCommit className="w-3.5 h-3.5 text-slate-500" />
              <span className="font-mono text-slate-300">
                {result.commitSha}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/25 transition-all font-semibold cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy PR Markdown'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1a243a] hover:bg-[#233252] border border-[#2b3d63] text-slate-200 transition-all font-semibold cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .md</span>
            </button>
            <button
              onClick={handleDownloadSarif}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 transition-all font-semibold cursor-pointer"
              title="Download standard SARIF 2.1.0 for GitHub Code Scanning"
            >
              <FileJson className="w-3.5 h-3.5" />
              <span>Export SARIF</span>
            </button>
          </div>
        </div>

        {/* PR Markdown Content Preview */}
        <div className="p-6 overflow-y-auto font-sans text-sm text-slate-200 space-y-4 bg-[#0a0d14]">
          <pre className="p-4 rounded-xl bg-[#0e1422] border border-[#1e2a40] text-xs font-mono whitespace-pre-wrap leading-relaxed text-slate-300 overflow-x-auto">
            {result.prBody}
          </pre>
        </div>
      </div>
    </div>
  );
};
