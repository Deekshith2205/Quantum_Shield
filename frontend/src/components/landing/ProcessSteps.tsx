import React from 'react';

const STEPS = [
  { number: '01', line1: 'DISCOVER', line2: 'RISKS' },
  { number: '02', line1: 'PRIORITIZE', line2: 'MIGRATION' },
  { number: '03', line1: 'SIMULATE', line2: 'SOLUTIONS' },
  { number: '04', line1: 'BUILD', line2: 'READINESS' },
];

interface ProcessStepsProps {
  className?: string;
}

export const ProcessSteps: React.FC<ProcessStepsProps> = ({ className = '' }) => {
  return (
    <>
      {/* Desktop & Tablet Vertical Presentation */}
      <div className={`hidden sm:flex flex-col justify-between select-none ${className}`}>
        {STEPS.map((step, idx) => (
          <div key={step.number} className="space-y-1.5">
            {/* Step Number: 14px, black */}
            <div className="font-mono text-[14px] font-bold text-[#0F172A] tracking-wider">
              {step.number}
            </div>

            {/* Step Action Labels: 11-12px uppercase, letter-spacing: 2px, gray */}
            <div className="text-[11.5px] font-semibold text-slate-500 tracking-[2px] uppercase leading-[1.3] font-sans">
              <div>{step.line1}</div>
              <div>{step.line2}</div>
            </div>

            {/* Thin horizontal separator */}
            {idx < STEPS.length - 1 && (
              <div className="w-6 border-b border-slate-200/90 pt-4 mb-2" />
            )}
          </div>
        ))}
      </div>

      {/* Mobile Compact Horizontal Presentation */}
      <div className="flex sm:hidden items-center justify-between w-full pt-4 mt-2 border-t border-slate-200/70 select-none">
        {STEPS.map((step) => (
          <div key={step.number} className="text-center space-y-0.5 px-1">
            <div className="font-mono text-xs font-bold text-[#0F172A]">
              {step.number}
            </div>
            <div className="text-[9.5px] font-semibold text-slate-500 tracking-wider uppercase leading-tight">
              <div>{step.line1}</div>
              <div>{step.line2}</div>
            </div>
          </div>
        ))}
      </div>
    </>
  );
};
