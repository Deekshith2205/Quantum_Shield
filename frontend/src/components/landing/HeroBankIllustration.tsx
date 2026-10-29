import React from 'react';

interface HeroBankIllustrationProps {
  className?: string;
}

export const HeroBankIllustration: React.FC<HeroBankIllustrationProps> = ({ className = '' }) => {
  return (
    <div className={`relative w-full select-none ${className}`}>
      {/* Top Right Label: BANKING SECURITY IN A POST-QUANTUM WORLD */}
      <div className="absolute top-2 right-12 sm:right-24 text-right z-10 pointer-events-none">
        <div className="text-[11px] sm:text-[12px] font-semibold text-slate-400 tracking-[0.2em] uppercase leading-tight font-mono">
          Banking Security
        </div>
        <div className="text-[11px] sm:text-[12px] font-semibold text-slate-400 tracking-[0.2em] uppercase leading-tight font-mono">
          In A Post-Quantum World
        </div>
        {/* Subtle drop line from label to architecture */}
        <div className="w-[1px] h-8 bg-slate-300 ml-auto mt-1 opacity-70" />
      </div>

      <svg
        viewBox="0 0 760 600"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-auto overflow-visible"
        aria-hidden="true"
      >
        <defs>
          {/* Subtle lavender gradient for the quantum aura behind bank */}
          <radialGradient
            id="quantumLavenderAuraRef"
            cx="48%"
            cy="46%"
            r="48%"
            fx="42%"
            fy="40%"
          >
            <stop offset="0%" stopColor="#ECEBFF" stopOpacity="0.9" />
            <stop offset="40%" stopColor="#E0E7FF" stopOpacity="0.55" />
            <stop offset="75%" stopColor="#EDE9FE" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#FCFCFA" stopOpacity="0" />
          </radialGradient>

          {/* Linear gradient for delicate quantum flow orbit curves */}
          <linearGradient id="orbitalGradientRef1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#5755D9" stopOpacity="0.7" />
            <stop offset="50%" stopColor="#818CF8" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#C7D2FE" stopOpacity="0.1" />
          </linearGradient>

          <linearGradient id="orbitalGradientRef2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#4F46E5" stopOpacity="0.55" />
            <stop offset="70%" stopColor="#A5B4FC" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#E0E7FF" stopOpacity="0.05" />
          </linearGradient>
        </defs>

        {/* 1. SOFT LAVENDER / INDIGO CELESTIAL QUANTUM AURA */}
        <circle
          cx="430"
          cy="250"
          r="170"
          fill="url(#quantumLavenderAuraRef)"
        />
        <ellipse
          cx="460"
          cy="235"
          rx="135"
          ry="135"
          fill="#EDE9FE"
          fillOpacity="0.45"
        />

        {/* 2. FLOWING ORBITAL CONTOUR LINES (Delicate Quantum Geometries) */}
        {/* Outer continuous swooping curve from top-left, wrapping around bank */}
        <path
          d="M 15 210 C 130 115, 270 80, 410 95 C 550 112, 645 180, 670 275 C 695 370, 605 465, 440 480 C 275 490, 180 420, 155 365 C 130 295, 180 200, 295 165 C 400 135, 520 165, 580 235"
          stroke="url(#orbitalGradientRef1)"
          strokeWidth="1.3"
          strokeDasharray="4 2"
          fill="none"
          opacity="0.9"
        />
        {/* Second delicate orbital loop around the central columns */}
        <path
          d="M 60 245 C 145 185, 250 150, 365 168 C 495 185, 590 245, 625 328 C 655 400, 580 490, 450 500 C 320 512, 215 450, 198 388"
          stroke="#94A3B8"
          strokeWidth="0.9"
          fill="none"
          opacity="0.55"
        />
        {/* Third fine geometric ellipse behind pediment */}
        <ellipse
          cx="430"
          cy="235"
          rx="205"
          ry="135"
          stroke="#C7D2FE"
          strokeWidth="1"
          fill="none"
          transform="rotate(-15 430 235)"
          opacity="0.75"
        />
        {/* Fine orbital tick marks along the curve */}
        <circle cx="310" cy="135" r="2.8" fill="#5755D9" opacity="0.75" />
        <circle cx="560" cy="172" r="2.2" fill="#818CF8" opacity="0.65" />
        <circle cx="665" cy="272" r="2.2" fill="#5755D9" opacity="0.6" />

        {/* 3. MODERN FINANCIAL DISTRICT SKYLINE (Background Glass High-Rises on Right) */}
        <g stroke="#94A3B8" strokeWidth="1.1" opacity="0.65" strokeLinecap="round" strokeLinejoin="round">
          {/* Skyscraper Tower 1 (Center Right) */}
          <polygon points="525,400 525,170 568,145 568,400" fill="#FFFFFF" fillOpacity="0.75" />
          <line x1="539" y1="162" x2="539" y2="400" />
          <line x1="554" y1="153" x2="554" y2="400" />
          {/* Horizontal floor dividers */}
          <line x1="525" y1="195" x2="568" y2="170" strokeWidth="0.7" />
          <line x1="525" y1="230" x2="568" y2="205" strokeWidth="0.7" />
          <line x1="525" y1="265" x2="568" y2="240" strokeWidth="0.7" />
          <line x1="525" y1="300" x2="568" y2="275" strokeWidth="0.7" />
          <line x1="525" y1="335" x2="568" y2="310" strokeWidth="0.7" />

          {/* Skyscraper Tower 2 (Tall Sharp Tower) */}
          <polygon points="580,400 580,115 610,85 628,108 628,400" fill="#FFFFFF" fillOpacity="0.85" />
          <line x1="610" y1="85" x2="610" y2="400" strokeWidth="1.3" />
          {/* Vertical grid glass mullions */}
          <line x1="595" y1="102" x2="595" y2="400" strokeWidth="0.7" />
          <line x1="620" y1="102" x2="620" y2="400" strokeWidth="0.7" />
          {/* Horizontal floor grid lines */}
          <line x1="580" y1="138" x2="628" y2="138" strokeWidth="0.6" />
          <line x1="580" y1="168" x2="628" y2="168" strokeWidth="0.6" />
          <line x1="580" y1="198" x2="628" y2="198" strokeWidth="0.6" />
          <line x1="580" y1="228" x2="628" y2="228" strokeWidth="0.6" />
          <line x1="580" y1="258" x2="628" y2="258" strokeWidth="0.6" />
          <line x1="580" y1="288" x2="628" y2="288" strokeWidth="0.6" />
          <line x1="580" y1="318" x2="628" y2="318" strokeWidth="0.6" />

          {/* Skyscraper Tower 3 (Far Right Stepped Tower) */}
          <polygon points="640,400 640,190 664,172 676,172 676,400" fill="#FFFFFF" fillOpacity="0.65" />
          <line x1="652" y1="183" x2="652" y2="400" strokeWidth="0.7" />
          <line x1="664" y1="172" x2="664" y2="400" strokeWidth="0.7" />
        </g>

        {/* 4. CLASSICAL BANK INSTITUTION (Grand Neoclassical Architecture) */}
        <g stroke="#1E293B" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" fill="none">
          {/* Outer Building Block Envelope */}
          <polygon
            points="200,410 200,240 520,240 520,410"
            fill="#FFFFFF"
            fillOpacity="0.96"
            stroke="#334155"
            strokeWidth="1.3"
          />

          {/* TRIANGULAR PEDIMENT (Roof Triangle) */}
          {/* Main outer pediment */}
          <polygon
            points="188,240 360,140 532,240"
            fill="#FFFFFF"
            stroke="#0F172A"
            strokeWidth="2"
          />
          {/* Inner pediment tympanum */}
          <polygon
            points="205,234 360,152 515,234"
            fill="#FAF9F6"
            stroke="#334155"
            strokeWidth="1.1"
          />
          {/* Cornice dentils under pediment rim */}
          <line x1="184" y1="242" x2="536" y2="242" stroke="#0F172A" strokeWidth="2.4" />
          <line x1="186" y1="248" x2="534" y2="248" stroke="#475569" strokeWidth="1.1" />
          {/* Dentil pattern ticks */}
          {Array.from({ length: 36 }).map((_, i) => (
            <line
              key={`dentil-lg-${i}`}
              x1={194 + i * 9.4}
              y1={243}
              x2={194 + i * 9.4}
              y2={247}
              stroke="#334155"
              strokeWidth="1.3"
            />
          ))}

          {/* "BANK" INSCRIPTION IN THE TYMPANUM */}
          <text
            x="360"
            y="214"
            textAnchor="middle"
            fontFamily="'Cinzel', 'Times New Roman', 'Baskerville', 'Playfair Display', serif"
            fontSize="21"
            fontWeight="bold"
            letterSpacing="0.32em"
            fill="#0F172A"
            stroke="none"
          >
            BANK
          </text>
          {/* Decorative flourish underline below "BANK" */}
          <line x1="318" y1="221" x2="402" y2="221" stroke="#64748B" strokeWidth="0.9" />
          <circle cx="360" cy="221" r="1.8" fill="#475569" stroke="none" />

          {/* ENTABLATURE & FRIEZE BEAM */}
          <rect x="194" y="249" width="332" height="22" fill="#F8FAFC" stroke="#1E293B" strokeWidth="1.4" />
          <line x1="194" y1="256" x2="526" y2="256" stroke="#64748B" strokeWidth="0.7" />
          <line x1="194" y1="264" x2="526" y2="264" stroke="#64748B" strokeWidth="0.7" />

          {/* 4 GRAND NEOCLASSICAL FLUTED COLUMNS */}
          {/* Column 1 (Leftmost) */}
          <g id="col-ref-1">
            <path d="M 215 271 L 249 271 L 245 281 L 219 281 Z" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <circle cx="220" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <circle cx="244" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <rect x="220" y="281" width="24" height="110" fill="#FFFFFF" stroke="#0F172A" strokeWidth="1.4" />
            <line x1="225" y1="281" x2="225" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="232" y1="281" x2="232" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="239" y1="281" x2="239" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <rect x="215" y="391" width="34" height="7" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <rect x="212" y="398" width="40" height="7" fill="#CBD5E1" stroke="#1E293B" strokeWidth="1.3" />
          </g>

          {/* Column 2 (Left-Center) */}
          <g id="col-ref-2">
            <path d="M 292 271 L 326 271 L 322 281 L 296 281 Z" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <circle cx="297" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <circle cx="321" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <rect x="297" y="281" width="24" height="110" fill="#FFFFFF" stroke="#0F172A" strokeWidth="1.4" />
            <line x1="302" y1="281" x2="302" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="309" y1="281" x2="309" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="316" y1="281" x2="316" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <rect x="292" y="391" width="34" height="7" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <rect x="289" y="398" width="40" height="7" fill="#CBD5E1" stroke="#1E293B" strokeWidth="1.3" />
          </g>

          {/* Column 3 (Right-Center) */}
          <g id="col-ref-3">
            <path d="M 394 271 L 428 271 L 424 281 L 398 281 Z" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <circle cx="399" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <circle cx="423" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <rect x="399" y="281" width="24" height="110" fill="#FFFFFF" stroke="#0F172A" strokeWidth="1.4" />
            <line x1="404" y1="281" x2="404" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="411" y1="281" x2="411" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="418" y1="281" x2="418" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <rect x="394" y="391" width="34" height="7" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <rect x="391" y="398" width="40" height="7" fill="#CBD5E1" stroke="#1E293B" strokeWidth="1.3" />
          </g>

          {/* Column 4 (Rightmost) */}
          <g id="col-ref-4">
            <path d="M 471 271 L 505 271 L 501 281 L 475 281 Z" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <circle cx="476" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <circle cx="500" cy="276" r="3.5" fill="none" stroke="#1E293B" strokeWidth="0.9" />
            <rect x="476" y="281" width="24" height="110" fill="#FFFFFF" stroke="#0F172A" strokeWidth="1.4" />
            <line x1="481" y1="281" x2="481" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="488" y1="281" x2="488" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <line x1="495" y1="281" x2="495" y2="391" stroke="#64748B" strokeWidth="0.8" />
            <rect x="471" y="391" width="34" height="7" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
            <rect x="468" y="398" width="40" height="7" fill="#CBD5E1" stroke="#1E293B" strokeWidth="1.3" />
          </g>

          {/* GRAND CENTRAL ARCHED DOUBLE DOORWAY */}
          <path
            d="M 339 405 L 339 322 C 339 308, 381 308, 381 322 L 381 405 Z"
            fill="#F1F5F9"
            stroke="#1E293B"
            strokeWidth="1.3"
          />
          <path
            d="M 344 405 L 344 324 C 344 314, 376 314, 376 324 L 376 405 Z"
            fill="#E2E8F0"
            stroke="#475569"
            strokeWidth="0.9"
          />
          <line x1="360" y1="328" x2="360" y2="405" stroke="#1E293B" strokeWidth="1.2" />
          <rect x="347" y="338" width="10" height="25" stroke="#64748B" strokeWidth="0.7" fill="#FFFFFF" />
          <rect x="363" y="338" width="10" height="25" stroke="#64748B" strokeWidth="0.7" fill="#FFFFFF" />
          <rect x="347" y="370" width="10" height="28" stroke="#64748B" strokeWidth="0.7" fill="#FFFFFF" />
          <rect x="363" y="370" width="10" height="28" stroke="#64748B" strokeWidth="0.7" fill="#FFFFFF" />
          {/* Fanlight radial lines */}
          <path d="M 344 324 C 344 315, 376 315, 376 324 Z" fill="#CBD5E1" stroke="#475569" strokeWidth="0.9" />
          <line x1="360" y1="324" x2="360" y2="315" stroke="#334155" strokeWidth="0.9" />
          <line x1="360" y1="324" x2="351" y2="317" stroke="#334155" strokeWidth="0.9" />
          <line x1="360" y1="324" x2="369" y2="317" stroke="#334155" strokeWidth="0.9" />

          {/* Left Arched Window */}
          <path
            d="M 258 380 L 258 312 C 258 302, 282 302, 282 312 L 282 380 Z"
            fill="#F8FAFC"
            stroke="#334155"
            strokeWidth="1.1"
          />
          <line x1="270" y1="307" x2="270" y2="380" stroke="#64748B" strokeWidth="0.7" />
          <line x1="258" y1="330" x2="282" y2="330" stroke="#64748B" strokeWidth="0.7" />
          <line x1="258" y1="355" x2="282" y2="355" stroke="#64748B" strokeWidth="0.7" />
          <rect x="256" y="380" width="28" height="4" fill="#E2E8F0" stroke="#475569" strokeWidth="0.9" />

          {/* Right Arched Window */}
          <path
            d="M 438 380 L 438 312 C 438 302, 462 302, 462 312 L 462 380 Z"
            fill="#F8FAFC"
            stroke="#334155"
            strokeWidth="1.1"
          />
          <line x1="450" y1="307" x2="450" y2="380" stroke="#64748B" strokeWidth="0.7" />
          <line x1="438" y1="330" x2="462" y2="330" stroke="#64748B" strokeWidth="0.7" />
          <line x1="438" y1="355" x2="462" y2="355" stroke="#64748B" strokeWidth="0.7" />
          <rect x="436" y="380" width="28" height="4" fill="#E2E8F0" stroke="#475569" strokeWidth="0.9" />

          {/* MONUMENTAL STEPS (Descending Podium Staircase) */}
          <polygon points="170,412 550,412 545,419 175,419" fill="#F1F5F9" stroke="#1E293B" strokeWidth="1.1" />
          <polygon points="163,419 557,419 552,426 168,426" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
          <polygon points="156,426 564,426 559,433 161,433" fill="#F1F5F9" stroke="#1E293B" strokeWidth="1.1" />
          <polygon points="149,433 571,433 566,440 154,440" fill="#E2E8F0" stroke="#1E293B" strokeWidth="1.1" />
          <polygon points="142,440 578,440 573,448 147,448" fill="#CBD5E1" stroke="#0F172A" strokeWidth="1.4" />
        </g>

        {/* 5. TREES ON THE LEFT (Fine Architectural Ink Branching) */}
        <g stroke="#334155" strokeLinecap="round" strokeLinejoin="round" fill="none">
          <path d="M 128 440 Q 132 385, 120 338 Q 112 300, 98 265" strokeWidth="2.8" />
          <path d="M 120 338 Q 140 308, 152 278" strokeWidth="1.8" />
          <path d="M 125 362 Q 146 344, 164 320" strokeWidth="1.6" />
          <path d="M 98 265 Q 86 235, 68 216" strokeWidth="1.4" />
          <path d="M 98 265 Q 116 240, 128 222" strokeWidth="1.4" />
          <path d="M 152 278 Q 170 260, 180 236" strokeWidth="1.3" />

          {/* Stippled leaf clusters */}
          <path
            d="M 50 240 C 38 205, 74 180, 104 192 C 134 174, 170 198, 164 228 C 188 252, 170 288, 140 282 C 122 306, 74 300, 62 276 C 38 270, 44 252, 50 240 Z"
            fill="#FFFFFF"
            fillOpacity="0.85"
            stroke="#475569"
            strokeWidth="1.1"
            strokeDasharray="2 2"
          />
          <path d="M 80 228 Q 68 210, 60 204" strokeWidth="0.9" />
          <path d="M 110 210 Q 116 192, 122 186" strokeWidth="0.9" />
          <path d="M 140 222 Q 155 204, 167 206" strokeWidth="0.9" />

          {/* Secondary smaller tree */}
          <path d="M 86 440 Q 84 402, 72 366 Q 62 336, 48 312" strokeWidth="2" />
          <path d="M 72 366 Q 88 346, 96 324" strokeWidth="1.3" />
          <path
            d="M 32 324 C 20 300, 44 282, 64 290 C 86 276, 110 294, 104 318 C 116 336, 98 354, 80 350 C 64 366, 38 354, 32 324 Z"
            fill="#FFFFFF"
            fillOpacity="0.85"
            stroke="#64748B"
            strokeWidth="0.9"
            strokeDasharray="2 1.5"
          />
        </g>

        {/* 6. GROUND LEVEL PAVEMENT & PEDESTRIANS */}
        <g stroke="#0F172A" strokeLinecap="round" strokeLinejoin="round" fill="none">
          <line x1="30" y1="448" x2="710" y2="448" strokeWidth="1.8" />
          <line x1="60" y1="456" x2="680" y2="456" stroke="#94A3B8" strokeWidth="0.9" />
          <line x1="80" y1="465" x2="660" y2="465" stroke="#CBD5E1" strokeWidth="0.7" />
          <line x1="110" y1="474" x2="630" y2="474" stroke="#E2E8F0" strokeWidth="0.5" />

          {/* Paver joint ticks */}
          {Array.from({ length: 22 }).map((_, i) => (
            <line
              key={`pave-ref-${i}`}
              x1={80 + i * 27}
              y1={449}
              x2={75 + i * 27}
              y2={465}
              stroke="#CBD5E1"
              strokeWidth="0.7"
            />
          ))}

          {/* PEDESTRIAN FIGURES (Minimalist Silhouettes) */}
          <g id="fig-ref-1" transform="translate(250, 420)">
            <circle cx="5" cy="5" r="3.2" fill="#1E293B" stroke="none" />
            <path d="M 3 8 L 7 8 L 9 22 L 1 22 Z" fill="#1E293B" stroke="none" />
            <line x1="3" y1="22" x2="1" y2="34" stroke="#1E293B" strokeWidth="1.6" />
            <line x1="7" y1="22" x2="9" y2="33" stroke="#1E293B" strokeWidth="1.6" />
          </g>

          <g id="fig-ref-2" transform="translate(355, 422)">
            <circle cx="5" cy="4" r="3" fill="#0F172A" stroke="none" />
            <path d="M 3 7 L 7 7 L 8 21 L 2 21 Z" fill="#0F172A" stroke="none" />
            <line x1="3" y1="21" x2="2" y2="33" stroke="#0F172A" strokeWidth="1.5" />
            <line x1="7" y1="21" x2="8" y2="32" stroke="#0F172A" strokeWidth="1.5" />
          </g>

          <g id="fig-ref-3" transform="translate(420, 421)">
            <circle cx="4" cy="4" r="2.9" fill="#334155" stroke="none" />
            <path d="M 2 7 L 6 7 L 7 21 L 1 21 Z" fill="#334155" stroke="none" />
            <line x1="2" y1="21" x2="1" y2="33" stroke="#334155" strokeWidth="1.4" />
            <line x1="6" y1="21" x2="7" y2="33" stroke="#334155" strokeWidth="1.4" />
          </g>

          <g id="fig-ref-4" transform="translate(540, 422)">
            <circle cx="4" cy="4" r="2.8" fill="#475569" stroke="none" />
            <path d="M 2 7 L 6 7 L 7 20 L 1 20 Z" fill="#475569" stroke="none" />
            <line x1="2" y1="20" x2="0" y2="32" stroke="#475569" strokeWidth="1.3" />
            <line x1="6" y1="20" x2="8" y2="32" stroke="#475569" strokeWidth="1.3" />
          </g>
        </g>
      </svg>
    </div>
  );
};
