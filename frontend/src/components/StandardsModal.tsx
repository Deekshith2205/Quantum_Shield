import React from 'react';
import { X, BookOpen, ExternalLink, ShieldCheck } from 'lucide-react';

interface StandardsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const StandardsModal: React.FC<StandardsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl rounded-2xl bg-white border border-slate-200 shadow-2xl p-6 sm:p-8 max-h-[90vh] overflow-y-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-100">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-[#EEF2FF] border border-[#5B5BD6]/20 flex items-center justify-center text-[#5B5BD6]">
              <BookOpen className="w-5 h-5 text-[#5B5BD6]" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                Post-Quantum Cryptography (PQC) Standards Reference
              </h2>
              <p className="text-xs text-slate-500">
                Official specifications published by NIST & IETF for post-quantum migration
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-4 text-xs text-slate-600">
          <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/80 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">
                NIST FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation)
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-100/70 text-indigo-700 font-semibold">
                FIPS 203 FINAL
              </span>
            </div>
            <p className="leading-relaxed text-slate-600">
              Primary post-quantum standard for general encryption and key establishment, derived from CRYSTALS-Kyber.
              Standard parameter sets: <strong>ML-KEM-512</strong> (Category 1), <strong>ML-KEM-768</strong> (Category 3 / Primary Recommendation), and <strong>ML-KEM-1024</strong> (Category 5).
              Enables hybrid deployment with classical Curve25519 (X25519Kyber768 / X25519MLKEM768 / RFC 9870).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/80 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">
                NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signatures)
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-100/70 text-indigo-700 font-semibold">
                FIPS 204 FINAL
              </span>
            </div>
            <p className="leading-relaxed text-slate-600">
              Primary digital signature algorithm derived from CRYSTALS-Dilithium. Replaces RSA and ECDSA signatures in PKI certificates and code signing.
              Parameter sets: <strong>ML-DSA-44</strong>, <strong>ML-DSA-65</strong> (recommended), and <strong>ML-DSA-87</strong>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/80 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">
                NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Signatures)
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-100/70 text-indigo-700 font-semibold">
                FIPS 205 FINAL
              </span>
            </div>
            <p className="leading-relaxed text-slate-600">
              Derived from SPHINCS+, provides a conservative fallback signature scheme relying solely on the security of hash functions rather than lattice problems. Ideal for high-assurance root CAs and firmware signing.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/80 space-y-2">
            <h3 className="text-sm font-semibold text-slate-900">Threat Model: Shor's vs. Grover's Algorithms</h3>
            <ul className="list-disc pl-4 space-y-1 text-slate-600 leading-relaxed">
              <li>
                <strong className="text-slate-800">Shor's Algorithm:</strong> Solves integer factorization and discrete logarithms in polynomial time. Completely breaks RSA, ECDSA, ECDH, Ed25519, and classical Diffie-Hellman.
              </li>
              <li>
                <strong className="text-slate-800">Grover's Algorithm:</strong> Offers quadratic speedup for unstructured brute-force search. Reduces effective security of AES-128 to ~64 bits. AES-256 retains ~128 bits, remaining quantum-resistant.
              </li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-[#18181B] hover:bg-black text-white font-medium text-xs transition cursor-pointer"
          >
            Close Reference
          </button>
        </div>
      </div>
    </div>
  );
};
