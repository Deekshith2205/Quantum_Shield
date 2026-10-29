import React from 'react';
import { DomainScannerInput } from './DomainScannerInput';
import { HeroBankIllustration } from './HeroBankIllustration';
import { ProcessSteps } from './ProcessSteps';

interface HeroSectionProps {
  onScan: (domain: string, port: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onScan,
  isLoading,
  currentDomain,
  initialAssetId,
}) => {
  return (
    <section className="w-full max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] pt-[72px] lg:pt-[82px] pb-12 lg:pb-18">
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.06fr] gap-8 lg:gap-10 items-start">
        {/* LEFT COLUMN: Editorial Typography & Domain Scanner (Occupies ~48%) */}
        <div className="space-y-7 pr-0 lg:pr-4">
          {/* Eyebrow: Exact 2 lines, uppercase, 12px, letter-spacing ~4px, muted gray, line-height 1.8 */}
          <div className="space-y-0.5">
            <p className="text-[12px] font-medium tracking-[4px] text-[#64748B] uppercase font-mono leading-[1.8]">
              POST-QUANTUM SECURITY FOR
            </p>
            <p className="text-[12px] font-medium tracking-[4px] text-[#64748B] uppercase font-mono leading-[1.8]">
              TODAY'S FINANCIAL SYSTEMS
            </p>
          </div>

          {/* Main Headline: 64-72px, font-weight 300-400, line-height 1.05, tracking -2px */}
          <h1 className="text-4xl sm:text-5xl lg:text-[66px] xl:text-[70px] font-light leading-[1.05] tracking-[-2px] text-[#0F172A]">
            See the <span className="text-[#5755D9] font-normal">Quantum</span>
            <br />
            <span className="text-[#5755D9] font-normal">Risks</span> in Your Bank.
            <br />
            <span className="whitespace-nowrap">Know What to Fix First.</span>
          </h1>

          {/* Editorial Subheadline: ~18px, line-height 1.55, max-w ~650px */}
          <p className="text-slate-600 text-[16.5px] sm:text-[18px] leading-[1.55] max-w-[650px] font-normal">
            QuantumShield scans your infrastructure, analyzes cryptographic vulnerabilities, understands your banking systems, and helps you prioritize migration to post-quantum cryptography — with clear, explainable risk analysis.
          </p>

          {/* Domain Scanner Input: ~650px wide, ~52px tall */}
          <div className="pt-2">
            <DomainScannerInput
              onScan={onScan}
              isLoading={isLoading}
              currentDomain={currentDomain}
              initialAssetId={initialAssetId}
            />
          </div>
        </div>

        {/* RIGHT COLUMN: Bank Illustration & Process Steps (Occupies ~52%) */}
        <div className="relative mt-6 lg:mt-[-10px] w-full">
          <div className="flex items-start justify-between">
            {/* Large Architectural Bank Illustration */}
            <div className="flex-1 w-full min-w-0">
              <HeroBankIllustration />
            </div>

            {/* Vertical Process Steps: positioned on the far right */}
            <div className="w-auto shrink-0 pl-3 sm:pl-5 flex flex-col justify-start pt-14 sm:pt-20">
              <ProcessSteps className="h-[380px] sm:h-[440px]" />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
