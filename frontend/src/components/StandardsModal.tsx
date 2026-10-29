import React from 'react';
import { X, BookOpen, ExternalLink, ShieldCheck } from 'lucide-react';

interface StandardsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const StandardsModal: React.FC<StandardsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="relative w-full max-w-3xl rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl p-6 max-h-[90vh] overflow-y-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <BookOpen className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white">Post-Quantum Cryptography (PQC) Standards Reference</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-4 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <h3 className="text-sm font-bold text-cyan-300">NIST FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation)</h3>
            <p className="leading-relaxed text-slate-400">
              Primary post-quantum standard for general encryption and key establishment, derived from CRYSTALS-Kyber.
              Standard parameters: <strong>ML-KEM-512</strong> (Category 1), <strong>ML-KEM-768</strong> (Category 3 / Recommended), and <strong>ML-KEM-1024</strong> (Category 5).
              Enables hybrid deployment with classical Curve25519 (X25519Kyber768 / X25519MLKEM768).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <h3 className="text-sm font-bold text-indigo-300">NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signatures)</h3>
            <p className="leading-relaxed text-slate-400">
              Primary digital signature algorithm derived from CRYSTALS-Dilithium. Replaces RSA and ECDSA signatures in PKI certificates and code signing.
              Parameter sets: <strong>ML-DSA-44</strong>, <strong>ML-DSA-65</strong> (recommended), and <strong>ML-DSA-87</strong>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <h3 className="text-sm font-bold text-sky-300">NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Signatures)</h3>
            <p className="leading-relaxed text-slate-400">
              Derived from SPHINCS+, provides a conservative fallback signature scheme relying solely on the security of hash functions rather than lattice problems. Ideal for high-assurance root CAs and firmware signing.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <h3 className="text-sm font-bold text-amber-300">Threat Model: Shor's vs. Grover's Algorithms</h3>
            <ul className="list-disc pl-4 space-y-1 text-slate-400 leading-relaxed">
              <li>
                <strong className="text-slate-200">Shor's Algorithm:</strong> Solves integer factorization and discrete logarithms in polynomial time. Completely breaks RSA, ECDSA, ECDH, Ed25519, and classical Diffie-Hellman.
              </li>
              <li>
                <strong className="text-slate-200">Grover's Algorithm:</strong> Offers quadratic speedup for unstructured brute-force search. Reduces effective security of AES-128 to ~64 bits. AES-256 retains ~128 bits, remaining quantum-resistant.
              </li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs transition cursor-pointer"
          >
            Close Reference
          </button>
        </div>
      </div>
    </div>
  );
};

