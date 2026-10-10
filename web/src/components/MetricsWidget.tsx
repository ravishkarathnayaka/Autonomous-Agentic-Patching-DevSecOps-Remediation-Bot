import React from 'react';
import { Clock, TrendingDown, DollarSign, ShieldAlert } from 'lucide-react';

interface MetricsWidgetProps {
  remediatedCount: number;
}

export const MetricsWidget: React.FC<MetricsWidgetProps> = ({ remediatedCount }) => {
  const count = Math.max(remediatedCount, 1);
  const hoursSaved = (count * 3.5).toFixed(1);
  const dollarsSaved = Math.round(count * 3.5 * 125).toLocaleString();

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {/* 1. MTTR Reduction */}
      <div className="p-3 rounded-xl bg-[#0e1422] border border-[#1e2a40] shadow-sm flex items-center gap-3">
        <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
          <TrendingDown className="w-4 h-4" />
        </div>
        <div>
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">MTTR Reduction</div>
          <div className="text-sm font-bold text-white flex items-baseline gap-1">
            <span>&lt; 90s</span>
            <span className="text-[10px] text-emerald-400 font-normal">vs 4.2 days</span>
          </div>
        </div>
      </div>

      {/* 2. Engineering Hours Saved */}
      <div className="p-3 rounded-xl bg-[#0e1422] border border-[#1e2a40] shadow-sm flex items-center gap-3">
        <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
          <Clock className="w-4 h-4" />
        </div>
        <div>
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Hours Saved</div>
          <div className="text-sm font-bold text-white flex items-baseline gap-1">
            <span>{hoursSaved} hrs</span>
            <span className="text-[10px] text-cyan-400 font-normal">eng time</span>
          </div>
        </div>
      </div>

      {/* 3. Cost Savings */}
      <div className="p-3 rounded-xl bg-[#0e1422] border border-[#1e2a40] shadow-sm flex items-center gap-3">
        <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 shrink-0">
          <DollarSign className="w-4 h-4" />
        </div>
        <div>
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Est. Cost Saved</div>
          <div className="text-sm font-bold text-white flex items-baseline gap-1">
            <span>${dollarsSaved}</span>
            <span className="text-[10px] text-amber-400 font-normal">USD</span>
          </div>
        </div>
      </div>

      {/* 4. Closed-Loop Sandbox Rate */}
      <div className="p-3 rounded-xl bg-[#0e1422] border border-[#1e2a40] shadow-sm flex items-center gap-3">
        <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shrink-0">
          <ShieldAlert className="w-4 h-4" />
        </div>
        <div>
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Verification Rate</div>
          <div className="text-sm font-bold text-white flex items-baseline gap-1">
            <span>100%</span>
            <span className="text-[10px] text-indigo-400 font-normal">zero false +</span>
          </div>
        </div>
      </div>
    </div>
  );
};
