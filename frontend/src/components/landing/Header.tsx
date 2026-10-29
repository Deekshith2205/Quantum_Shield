import React from 'react';
import { Sun, ArrowRight, ShieldCheck, Download } from 'lucide-react';

interface HeaderProps {
  activeView: 'scanner' | 'catalog' | 'risk' | 'simulator';
  onSelectView: (view: 'scanner' | 'catalog' | 'risk' | 'simulator') => void;
  onOpenDocumentation: () => void;
  onOpenExportModal?: () => void;
  hasScanData?: boolean;
  onGetStarted?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  onSelectView,
  onOpenDocumentation,
  onOpenExportModal,
  hasScanData = false,
  onGetStarted,
}) => {
  return (
    <header className="sticky top-0 z-50 w-full bg-[#FCFCFA]/95 backdrop-blur-md border-b border-slate-200/60 transition-colors">
      <div className="max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] h-[80px] flex items-center justify-between">
        {/* Brand Logo & Wordmark (Starts ~85px from left edge) */}
        <div
          onClick={() => onSelectView('scanner')}
          className="flex items-center space-x-2.5 cursor-pointer group select-none shrink-0"
        >
          {/* Stylized QuantumShield Badge */}
          <div className="w-9 h-9 rounded-xl bg-[#F4F3FF] border border-[#5755D9]/30 flex items-center justify-center text-[#5755D9] shadow-2xs group-hover:border-[#5755D9]/60 transition-colors">
            <ShieldCheck className="w-5 h-5 text-[#5755D9]" strokeWidth={2} />
          </div>

          <div className="flex items-center text-[19px] font-semibold tracking-tight">
            <span className="text-[#0F172A] font-bold">Quantum</span>
            <span className="text-[#5755D9] font-semibold">Shield</span>
          </div>
        </div>

        {/* Center / Right Navigation Links */}
        <nav className="hidden md:flex items-center space-x-7 lg:space-x-9 text-[14.5px]">
          <button
            type="button"
            onClick={() => onSelectView('scanner')}
            className={`font-medium transition-colors cursor-pointer py-1 relative ${
              activeView === 'scanner'
                ? 'text-[#0F172A] font-semibold after:absolute after:bottom-[-29px] after:left-0 after:right-0 after:h-[2px] after:bg-[#5755D9] after:rounded-full'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Scanner
          </button>

          <button
            type="button"
            onClick={() => onSelectView('catalog')}
            className={`font-medium transition-colors cursor-pointer py-1 relative ${
              activeView === 'catalog'
                ? 'text-[#0F172A] font-semibold after:absolute after:bottom-[-29px] after:left-0 after:right-0 after:h-[2px] after:bg-[#5755D9] after:rounded-full'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Banking Systems
          </button>

          <button
            type="button"
            onClick={() => onSelectView('risk')}
            className={`font-medium transition-colors cursor-pointer py-1 relative ${
              activeView === 'risk'
                ? 'text-[#0F172A] font-semibold after:absolute after:bottom-[-29px] after:left-0 after:right-0 after:h-[2px] after:bg-[#5755D9] after:rounded-full'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Prioritization Engine
          </button>

          <button
            type="button"
            onClick={() => onSelectView('simulator')}
            className={`font-medium transition-colors cursor-pointer py-1 relative ${
              activeView === 'simulator'
                ? 'text-[#0F172A] font-semibold after:absolute after:bottom-[-29px] after:left-0 after:right-0 after:h-[2px] after:bg-[#5755D9] after:rounded-full'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            What-If Simulator
          </button>

          <button
            type="button"
            onClick={onOpenDocumentation}
            className="font-medium text-slate-600 hover:text-slate-900 transition-colors cursor-pointer py-1"
          >
            Documentation
          </button>
        </nav>

        {/* Right Section Actions */}
        <div className="flex items-center space-x-3 sm:space-x-4 shrink-0">
          {/* Optional Export Report when scan data is available */}
          {hasScanData && onOpenExportModal && (
            <button
              type="button"
              onClick={onOpenExportModal}
              className="hidden lg:flex items-center space-x-1.5 px-3.5 py-2 rounded-[10px] border border-slate-200 text-xs text-slate-700 hover:text-slate-900 hover:bg-slate-50 transition cursor-pointer font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          )}

          {/* Light/Dark Appearance Icon (Sun icon as shown in reference) */}
          <button
            type="button"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer focus:outline-none"
            aria-label="Appearance Mode"
            title="Light appearance mode active"
          >
            <Sun className="w-4 h-4 text-slate-500" strokeWidth={1.8} />
          </button>

          {/* Get Started Button (~140px wide, ~48px tall) */}
          <button
            type="button"
            onClick={onGetStarted || (() => onSelectView('scanner'))}
            className="w-[136px] sm:w-[140px] h-[46px] sm:h-[48px] bg-[#18181B] hover:bg-black text-white text-xs sm:text-[13.5px] font-medium rounded-[10px] flex items-center justify-center space-x-1.5 transition-all shadow-xs cursor-pointer group"
          >
            <span>Get Started</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
          </button>
        </div>
      </div>

      {/* Mobile Navigation Dropdown Bar */}
      <div className="md:hidden flex items-center justify-around border-t border-slate-100 px-3 py-2 bg-[#FCFCFA]/95 text-xs">
        <button
          onClick={() => onSelectView('scanner')}
          className={`py-1 px-2 rounded font-medium ${
            activeView === 'scanner' ? 'text-[#5755D9] font-semibold' : 'text-slate-600'
          }`}
        >
          Scanner
        </button>
        <button
          onClick={() => onSelectView('catalog')}
          className={`py-1 px-2 rounded font-medium ${
            activeView === 'catalog' ? 'text-[#5755D9] font-semibold' : 'text-slate-600'
          }`}
        >
          Banking (5)
        </button>
        <button
          onClick={() => onSelectView('risk')}
          className={`py-1 px-2 rounded font-medium ${
            activeView === 'risk' ? 'text-[#5755D9] font-semibold' : 'text-slate-600'
          }`}
        >
          Priority
        </button>
        <button
          onClick={() => onSelectView('simulator')}
          className={`py-1 px-2 rounded font-medium ${
            activeView === 'simulator' ? 'text-[#5755D9] font-semibold' : 'text-slate-600'
          }`}
        >
          What-If
        </button>
        <button
          onClick={onOpenDocumentation}
          className="py-1 px-2 rounded font-medium text-slate-600"
        >
          Docs
        </button>
      </div>
    </header>
  );
};
