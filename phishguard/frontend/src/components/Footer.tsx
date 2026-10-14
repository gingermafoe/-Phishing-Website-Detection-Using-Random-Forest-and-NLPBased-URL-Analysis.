import React from "react";
import { Shield, Lock } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-surface-border bg-surface py-12 text-gray-400">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-8 border-b border-surface-border/60">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
              <Shield className="h-4 w-4" aria-hidden="true" />
            </div>
            <div>
              <span className="font-mono text-base font-bold tracking-wider text-white">
                PHISHGUARD
              </span>
              <p className="text-xs text-gray-500">
                Phishing Website Detection Using Random Forest
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-6 text-xs font-mono text-gray-400">
            <a href="#scanner" className="hover:text-white transition-colors">
              Scanner
            </a>
            <a href="#how-it-works" className="hover:text-white transition-colors">
              How It Works
            </a>
            <a href="#model" className="hover:text-white transition-colors">
              Model
            </a>
            <a href="#features" className="hover:text-white transition-colors">
              Features
            </a>
          </div>
        </div>

        {/* University / Academic Project Context */}
        <div className="mt-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs text-gray-500">
          <p className="leading-relaxed">
            University Machine Learning + Cybersecurity Project. Powered by scikit-learn and FastAPI.
          </p>
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <Lock className="h-3 w-3 text-primary" aria-hidden="true" />
            <span>ZERO-CRAWL VERIFIED PIPELINE</span>
          </div>
        </div>

        {/* Disclaimer */}
        <div className="mt-6 rounded-lg border border-surface-border/40 bg-background/50 p-4 text-[11px] text-gray-500 leading-relaxed text-center sm:text-left">
          <strong>Academic Disclaimer:</strong> PhishGuard provides a machine-learning based assessment and should not be treated as a guarantee of website safety. It is designed for cybersecurity research and intelligence augmentation.
        </div>
      </div>
    </footer>
  );
};
