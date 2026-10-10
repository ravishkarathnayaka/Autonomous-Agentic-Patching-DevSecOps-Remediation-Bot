import React from 'react';
import { ShieldCheck, Award, FileCheck } from 'lucide-react';

interface ComplianceBadgeProps {
  cwe: string[];
}

export const ComplianceBadge: React.FC<ComplianceBadgeProps> = ({ cwe }) => {
  const cweStr = cwe.join(' ').toUpperCase();
  const isCryptoOrSecret = cweStr.includes('CWE-327') || cweStr.includes('CWE-798');
  
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
        <ShieldCheck className="w-3 h-3" />
        SOC2 Type II
      </span>
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
        <Award className="w-3 h-3" />
        ISO 27001 (A.8.28)
      </span>
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
        <FileCheck className="w-3 h-3" />
        OWASP Top 10
      </span>
      {isCryptoOrSecret && (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold">
          PCI-DSS Dual Sign-off
        </span>
      )}
    </div>
  );
};
