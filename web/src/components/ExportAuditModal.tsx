import React, { useState } from 'react';
import { X, Download, Copy, Check, FileCode, Shield } from 'lucide-react';
import { RemediationResult } from '../types';

interface ExportAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: RemediationResult | null;
}

export const ExportAuditModal: React.FC<ExportAuditModalProps> = ({
  isOpen,
  onClose,
  result
}) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const sarifPayload = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Autonomous-DevSecOps-Bot",
            version: "2.0.0",
            rules: [
              {
                id: result?.prTitle || "SECURITY-FINDING",
                name: "Autonomous Patch Remediation",
                shortDescription: { text: result?.explanation || "Security finding remediated." }
              }
            ]
          }
        },
        results: [
          {
            ruleId: result?.prTitle || "SECURITY-FINDING",
            level: "none",
            message: { text: "Vulnerability resolved by autonomous patch agent." },
            status: result?.status === 'SUCCESS' ? 'passed' : 'failed'
          }
        ]
      }
    ]
  };

  const sarifString = JSON.stringify(sarifPayload, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(sarifString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([sarifString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'remediation-report.sarif';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-[#0d131f] border border-[#23324d] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2a3e] bg-[#0c101a]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Export Audit &amp; SARIF Report</h3>
              <p className="text-xs text-slate-400">OASIS SARIF 2.1.0 compatible with GitHub Code Scanning</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto font-mono text-xs text-slate-300 bg-[#090d16]">
          <pre className="p-4 rounded-xl bg-[#06080e] border border-[#1b2537] overflow-x-auto text-emerald-400">
            {sarifString}
          </pre>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-3.5 border-t border-[#1e2a3e] bg-[#0c101a]">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#141d2e] hover:bg-[#1c2940] text-slate-300 text-xs font-semibold border border-[#253654] transition-all cursor-pointer"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>{copied ? 'Copied!' : 'Copy SARIF'}</span>
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-all shadow-lg shadow-cyan-600/20 cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Download .sarif</span>
          </button>
        </div>
      </div>
    </div>
  );
};
