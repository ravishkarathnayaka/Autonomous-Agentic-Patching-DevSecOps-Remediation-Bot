import React, { useState } from 'react';
import { FileCode, Copy, Check, Download, ShieldCheck } from 'lucide-react';

interface DiffViewerProps {
  diffText?: string;
  explanation?: string;
  filePath?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diffText, explanation, filePath }) => {
  const [copied, setCopied] = useState(false);

  if (!diffText) {
    return (
      <div className="bg-[#101624] border border-[#1e293b] rounded-2xl p-8 text-center flex flex-col items-center justify-center min-h-[300px]">
        <FileCode className="w-12 h-12 text-slate-700 mb-3" />
        <p className="text-sm font-medium text-slate-400">No patch generated yet</p>
        <p className="text-xs text-slate-600 mt-1 max-w-sm">
          Select a vulnerability and click Launch to trigger the Patch Agent diff synthesis.
        </p>
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(diffText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([diffText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'remediation.patch';
    link.click();
    URL.revokeObjectURL(url);
  };

  const lines = diffText.split('\n');

  return (
    <div className="bg-[#101624] border border-[#1e293b] rounded-2xl overflow-hidden shadow-xl flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 bg-[#0d121c] border-b border-[#1e293b] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            {filePath || 'target_repo/patch.diff'}
          </span>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase">
            Unified Git Diff
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#172033] hover:bg-[#1f2b45] text-slate-300 hover:text-white transition-all text-xs font-medium"
            title="Copy patch diff"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#172033] hover:bg-[#1f2b45] text-slate-300 hover:text-white transition-all text-xs font-medium"
            title="Download .patch"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Download</span>
          </button>
        </div>
      </div>

      {/* Code diff lines */}
      <div className="p-4 font-mono text-xs overflow-x-auto bg-[#0a0d14] max-h-[380px] overflow-y-auto leading-relaxed">
        {lines.map((line, idx) => {
          let bg = 'text-slate-400';
          let border = '';
          if (line.startsWith('+') && !line.startsWith('+++')) {
            bg = 'bg-emerald-950/40 text-emerald-300 font-medium';
            border = 'border-l-2 border-emerald-500 pl-2';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            bg = 'bg-red-950/40 text-red-300 font-medium';
            border = 'border-l-2 border-red-500 pl-2';
          } else if (line.startsWith('@@')) {
            bg = 'text-cyan-400 font-bold bg-cyan-950/20 py-0.5';
          } else if (line.startsWith('---') || line.startsWith('+++')) {
            bg = 'text-slate-500 font-bold';
          }

          return (
            <div key={idx} className={`py-0.5 px-1.5 rounded-sm ${bg} ${border}`}>
              {line || ' '}
            </div>
          );
        })}
      </div>

      {/* Remediation Rationale */}
      {explanation && (
        <div className="p-4 bg-[#0d131f] border-t border-[#1e293b]">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 mb-1.5">
            <ShieldCheck className="w-4 h-4" />
            <span>Remediation Rationale</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {explanation}
          </p>
        </div>
      )}
    </div>
  );
};
