import React, { useState } from 'react';
import { X, Copy, Check, Download } from 'lucide-react';
import type { ScanResponse } from '../types/scan';

interface JsonExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  data: ScanResponse | null;
}

export const JsonExportModal: React.FC<JsonExportModalProps> = ({ isOpen, onClose, data }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !data) return null;

  const jsonString = JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `quantumshield-assessment-${data.target.domain}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl rounded-2xl bg-white border border-slate-200 shadow-2xl p-6 sm:p-8 max-h-[90vh] flex flex-col space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 font-mono">Structured Assessment JSON Report</h2>
            <p className="text-xs text-slate-500">Target: {data.target.domain}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Code Viewer */}
        <div className="flex-1 overflow-auto rounded-xl bg-slate-50 p-4 border border-slate-200 font-mono text-xs text-slate-800">
          <pre className="whitespace-pre">{jsonString}</pre>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-2 shrink-0">
          <span className="text-xs text-slate-500 font-mono">
            {jsonString.length} bytes · Validated Schema
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs transition cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4 text-slate-500" />}
              <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-[#18181B] hover:bg-black text-white font-medium text-xs transition cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Download File</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
