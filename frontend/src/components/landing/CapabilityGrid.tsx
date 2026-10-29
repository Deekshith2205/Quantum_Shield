import React from 'react';
import { Search, BarChart3, Sliders, FileText, ArrowRight } from 'lucide-react';

interface CapabilityGridProps {
  onStartScanning: () => void;
  onViewRiskModel: () => void;
  onTrySimulation: () => void;
  onExploreBankingSystems: () => void;
  className?: string;
}

export const CapabilityGrid: React.FC<CapabilityGridProps> = ({
  onStartScanning,
  onViewRiskModel,
  onTrySimulation,
  onExploreBankingSystems,
  className = '',
}) => {
  const capabilities = [
    {
      id: 'scanner',
      title: 'Cryptographic Scanner',
      description:
        'Analyze TLS configurations, certificates, and cryptographic algorithms for quantum vulnerabilities.',
      cta: 'Start Scanning →',
      action: onStartScanning,
      icon: <Search className="w-5 h-5 text-[#5755D9]" strokeWidth={1.8} />,
      badgeBg: 'bg-[#F4F3FF]',
    },
    {
      id: 'risk',
      title: 'Banking Risk Analysis',
      description:
        'Combine technical findings with business context, data lifetime, and migration effort into a clear priority.',
      cta: 'View Risk Model →',
      action: onViewRiskModel,
      icon: <BarChart3 className="w-5 h-5 text-[#0284C7]" strokeWidth={1.8} />,
      badgeBg: 'bg-[#F0F7FF]',
    },
    {
      id: 'simulation',
      title: 'What-If Migration Simulator',
      description:
        'See how your risk changes when you replace vulnerable cryptographic mechanisms with post-quantum standards.',
      cta: 'Try a Simulation →',
      action: onTrySimulation,
      icon: <Sliders className="w-5 h-5 text-[#7C3AED]" strokeWidth={1.8} />,
      badgeBg: 'bg-[#F5F3FF]',
    },
    {
      id: 'remediation',
      title: 'Actionable Remediation',
      description:
        'Get clear, explainable recommendations on what to fix first, with focus on your most critical banking systems.',
      cta: 'Explore Banking Systems →',
      action: onExploreBankingSystems,
      icon: <FileText className="w-5 h-5 text-[#4F46E5]" strokeWidth={1.8} />,
      badgeBg: 'bg-[#EEF2FF]',
    },
  ];

  return (
    <section className={`w-full max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] ${className}`}>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 border-t border-slate-200/80 pt-12 pb-24">
        {capabilities.map((cap, idx) => (
          <div
            key={cap.id}
            className={`flex flex-col justify-between py-6 lg:py-2 px-0 sm:px-6 lg:px-8 ${
              idx < capabilities.length - 1 ? 'lg:border-r lg:border-slate-200/80' : ''
            } ${idx > 0 && idx % 2 === 0 ? 'border-t md:border-t-0' : ''}`}
          >
            <div>
              {/* Rounded Icon Badge */}
              <div
                className={`w-11 h-11 rounded-2xl ${cap.badgeBg} flex items-center justify-center shadow-2xs transition-transform hover:scale-105`}
              >
                {cap.icon}
              </div>

              {/* Title */}
              <h3 className="text-base sm:text-[17px] font-semibold text-[#0F172A] mt-5 mb-2.5 tracking-tight">
                {cap.title}
              </h3>

              {/* Description */}
              <p className="text-slate-500 text-xs sm:text-[13.5px] leading-relaxed mb-6 font-normal">
                {cap.description}
              </p>
            </div>

            {/* CTA Link */}
            <div>
              <button
                type="button"
                onClick={cap.action}
                className="text-xs sm:text-[13.5px] font-medium text-[#5755D9] hover:text-[#4338CA] flex items-center space-x-1.5 transition-colors group cursor-pointer focus:outline-none"
              >
                <span>{cap.cta.replace(' →', '')}</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};
