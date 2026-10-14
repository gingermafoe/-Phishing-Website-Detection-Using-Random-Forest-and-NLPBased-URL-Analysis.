import React from "react";
import { ShieldCheck, Zap, Lock, Terminal } from "lucide-react";
import { UrlScanner } from "./UrlScanner";
import type { AnalysisStatus } from "../types/api";

interface HeroProps {
  status: AnalysisStatus;
  errorMessage: string | null;
  onAnalyze: (url: string) => void;
}

export const Hero: React.FC<HeroProps> = ({
  status,
  errorMessage,
  onAnalyze,
}) => {
  return (
    <section className="relative overflow-hidden pt-12 pb-16 sm:pt-20 sm:pb-24 text-center px-4">
      {/* Subtle background ambient radial gradient */}
      <div
        className="pointer-events-none absolute left-1/2 top-0 -translate-x-1/2 -translate-y-1/2 h-96 w-[600px] rounded-full bg-primary/10 blur-[120px]"
        aria-hidden="true"
      />

      <div className="relative mx-auto max-w-4xl">
        {/* Security Badge */}
        <div className="inline-flex items-center gap-2 rounded-full border border-surface-border bg-surface px-3.5 py-1 text-xs font-mono text-gray-300 mb-6">
          <Terminal className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
          <span>CYBERSECURITY INTELLIGENCE ENGINE</span>
        </div>

        {/* Large Heading */}
        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white mb-4">
          Is this URL safe?
        </h1>

        {/* Supporting Text */}
        <p className="mx-auto max-w-2xl text-base sm:text-lg text-gray-400 mb-10 leading-relaxed">
          Analyze any website link using our machine learning classifier. PhishGuard evaluates 21 lexical features in real time without executing suspicious network requests.
        </p>

        {/* Scanner Form */}
        <UrlScanner
          status={status}
          errorMessage={errorMessage}
          onAnalyze={onAnalyze}
        />

        {/* Key Architectural Highlights */}
        <div className="mt-12 grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto pt-8 border-t border-surface-border/60">
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-gray-400">
            <Zap className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
            <span>Zero-Crawl Safe Analysis</span>
          </div>
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-gray-400">
            <ShieldCheck className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
            <span>Random Forest Model</span>
          </div>
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-gray-400">
            <Lock className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
            <span>21 Lexical Features</span>
          </div>
        </div>
      </div>
    </section>
  );
};
