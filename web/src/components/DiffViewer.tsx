import React, { useState } from 'react';
import { FileCode, Copy, Check, Download, ShieldCheck, AlertTriangle, Code, ArrowRight } from 'lucide-react';

interface DiffViewerProps {
  diffText?: string;
  explanation?: string;
  filePath?: string;
  initialSourceCode?: string;
  vulnerableCode?: string;
  findingTitle?: string;
  cwe?: string[];
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  diffText,
  explanation,
  filePath,
  initialSourceCode,
  vulnerableCode,
  findingTitle,
  cwe
}) => {
  const [copied, setCopied] = useState(false);

  // If a patch diff exists, render the unified diff
  if (diffText) {
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
            <FileCode className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-mono font-semibold text-slate-200">
              {filePath || 'target_repo/patch.diff'}
            </span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 uppercase flex items-center gap-1">
              <Check className="w-3 h-3" />
              Surgical Patch Synthesized
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
              <span>Threat Mitigation Rationale</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {explanation}
            </p>
          </div>
        )}
      </div>
    );
  }

  // If no patch has been generated yet, show the target vulnerable source code!
  const sourceLines = initialSourceCode ? initialSourceCode.split('\n') : [];

  return (
    <div className="bg-[#101624] border border-[#1e293b] rounded-2xl overflow-hidden shadow-xl flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 bg-[#0d121c] border-b border-[#1e293b] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-amber-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            {filePath || 'target_repo/app.py'}
          </span>
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 uppercase flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            Vulnerable Target Code
          </span>
        </div>

        {cwe && cwe.length > 0 && (
          <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {cwe[0]}
          </span>
        )}
      </div>

      {/* Code preview lines */}
      <div className="p-4 font-mono text-xs overflow-x-auto bg-[#0a0d14] max-h-[380px] overflow-y-auto leading-relaxed">
        {sourceLines.length > 0 ? (
          sourceLines.map((line, idx) => {
            // Check if this line is part of the vulnerable code snippet
            const isVulnerable = vulnerableCode && vulnerableCode.includes(line.trim()) && line.trim().length > 3;

            return (
              <div
                key={idx}
                className={`flex items-start py-0.5 px-2 rounded ${
                  isVulnerable
                    ? 'bg-red-950/40 text-red-200 border-l-2 border-red-500 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span className="w-7 select-none text-slate-600 text-right pr-3 font-mono text-[11px]">
                  {idx + 1}
                </span>
                <span className="flex-1 whitespace-pre">{line || ' '}</span>
                {isVulnerable && (
                  <span className="select-none text-[10px] text-red-400 bg-red-500/10 px-1.5 py-0.2 rounded font-sans uppercase font-bold ml-2">
                    Vulnerable
                  </span>
                )}
              </div>
            );
          })
        ) : (
          <div className="text-slate-500 italic py-6 text-center">
            No source code loaded.
          </div>
        )}
      </div>

      {/* Threat details banner */}
      <div className="p-3.5 bg-[#0e1422] border-t border-[#1e293b] flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <p className="text-xs text-slate-300">
            <span className="font-semibold text-white">{findingTitle || 'Vulnerability detected'}.</span>{' '}
            Click <span className="text-cyan-400 font-semibold uppercase">Run Remediation Bot</span> above to generate and test the surgical fix.
          </p>
        </div>
      </div>
    </div>
  );
};
