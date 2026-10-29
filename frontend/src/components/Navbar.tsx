import React from 'react';
import { Shield, Cpu, Download, BookOpen, CheckCircle2, AlertCircle } from 'lucide-react';

interface NavbarProps {
  onOpenStandardsModal: () => void;
  onOpenExportModal: () => void;
  hasScanData: boolean;
  backendOnline: boolean;
  activeView: 'scanner' | 'catalog';
  onSelectView: (view: 'scanner' | 'catalog') => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenStandardsModal,
  onOpenExportModal,
  hasScanData,
  backendOnline,
  activeView,
  onSelectView,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onSelectView('scanner')}>
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-600/20 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-950/50">
              <Shield className="w-5 h-5 text-cyan-400" />
              <Cpu className="w-3 h-3 text-indigo-400 absolute bottom-1 right-1" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-wider bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
                  QUANTUMSHIELD
                </span>
                <span className="hidden sm:inline-flex text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-semibold tracking-wider">
                  Banking Audit
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Banking Security Audit & Zero-Trust Readiness Platform
              </p>
            </div>
          </div>

          {/* Primary View Navigation Switcher */}
          <nav className="hidden md:flex items-center space-x-1 p-1 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
            <button
              onClick={() => onSelectView('scanner')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition cursor-pointer ${
                activeView === 'scanner'
                  ? 'bg-gradient-to-r from-cyan-600/90 to-indigo-600/90 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Domain Scanner
            </button>
            <button
              onClick={() => onSelectView('catalog')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition cursor-pointer flex items-center space-x-1.5 ${
                activeView === 'catalog'
                  ? 'bg-gradient-to-r from-cyan-600/90 to-indigo-600/90 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>Banking Systems</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800">
                5
              </span>
            </button>
          </nav>
        </div>

        {/* Actions */}
        <div className="flex items-center space-x-3">
          {/* Backend Status indicator */}
          <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
            {backendOnline ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-slate-300 font-mono text-[11px]">Backend Active</span>
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                <span className="text-rose-400 font-mono text-[11px]">Backend Offline</span>
              </>
            )}
          </div>

          <button
            onClick={onOpenStandardsModal}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs text-slate-300 hover:text-white transition shadow-sm"
          >
            <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">PQC Standards</span>
          </button>

          <button
            onClick={onOpenExportModal}
            disabled={!hasScanData}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition shadow-sm ${
              hasScanData
                ? 'bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/50 text-cyan-300 cursor-pointer'
                : 'bg-slate-900/50 border border-slate-800 text-slate-600 cursor-not-allowed'
            }`}
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export Report</span>
          </button>
        </div>
      </div>
    </header>
  );
};

