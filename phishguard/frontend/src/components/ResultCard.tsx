import React from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  Cpu,
  Layers,
  Zap,
  Sparkles,
  HelpCircle,
} from "lucide-react";
import type { AnalyzeResponse } from "../types/api";
import { RiskScore } from "./RiskScore";

interface ResultCardProps {
  result: AnalyzeResponse;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result }) => {
  const isLegitimate = result.label === 1;
  const isPhishing = result.label === 0;

  // Format phishing probability as percentage
  // In the backend: if label == 1, probability is Legit prob, risk_score is round(P(phish)*100)
  // For clarity, display Phishing Probability explicitly
  const phishingProbPct = result.risk_score;
  const legitProbPct = 100 - result.risk_score;

  return (
    <section
      id="result-panel"
      className="mx-auto mt-8 max-w-4xl animate-fadeIn"
      aria-live="polite"
      aria-label="URL Analysis Result"
    >
      <div
        className={`glass-panel-elevated overflow-hidden rounded-2xl border transition-all duration-300 ${
          isLegitimate
            ? "border-cyber-safeBorder glow-safe"
            : "border-cyber-dangerBorder glow-danger"
        }`}
      >
        {/* Top Header Banner */}
        <div
          className={`flex flex-col sm:flex-row items-start sm:items-center justify-between border-b px-6 py-5 ${
            isLegitimate
              ? "border-cyber-safeBorder/40 bg-cyber-safeSubtle/40"
              : "border-cyber-dangerBorder/40 bg-cyber-dangerSubtle/40"
          }`}
        >
          <div className="flex items-center gap-3.5">
            <div
              className={`flex h-12 w-12 items-center justify-center rounded-xl border ${
                isLegitimate
                  ? "border-cyber-safe/40 bg-cyber-safe/10 text-cyber-safe"
                  : "border-cyber-danger/40 bg-cyber-danger/10 text-cyber-danger"
              }`}
            >
              {isLegitimate ? (
                <ShieldCheck className="h-7 w-7" aria-hidden="true" />
              ) : (
                <ShieldAlert className="h-7 w-7" aria-hidden="true" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`font-mono text-xs font-bold uppercase tracking-wider ${
                    isLegitimate ? "text-cyber-safe" : "text-cyber-danger"
                  }`}
                >
                  {isLegitimate ? "SAFE" : "THREAT DETECTED"}
                </span>
                <span className="text-gray-500">•</span>
                <span className="text-xs text-gray-400 font-mono">
                  Random Forest ML
                </span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                {isLegitimate ? "LEGITIMATE URL" : "PHISHING URL"}
              </h2>
            </div>
          </div>

          <div className="mt-3 sm:mt-0 flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-xs font-medium ${
                isLegitimate
                  ? "bg-cyber-safe/10 text-cyber-safe border border-cyber-safe/30"
                  : "bg-cyber-danger/10 text-cyber-danger border border-cyber-danger/30"
              }`}
            >
              {isLegitimate ? "Verified Clean" : "High Risk Signature"}
            </span>
          </div>
        </div>

        {/* Main Result Content */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 sm:p-8">
          {/* Left: Risk Score Gauge */}
          <div className="flex flex-col items-center justify-center rounded-xl border border-surface-border bg-surface/60 p-4">
            <RiskScore score={result.risk_score} />
          </div>

          {/* Middle: Probabilities & Classification */}
          <div className="md:col-span-2 flex flex-col justify-between space-y-4">
            <div>
              <h3 className="text-sm font-semibold tracking-wide text-gray-400 uppercase font-mono">
                Model Classification Assessment
              </h3>
              <p className="mt-1 text-sm text-gray-300 leading-relaxed">
                {isLegitimate ? (
                  <>
                    The Random Forest decision ensemble evaluated the lexical and structural properties of this URL and classified it as{" "}
                    <strong className="text-cyber-safe font-semibold">legitimate</strong>.
                  </>
                ) : (
                  <>
                    The Random Forest decision ensemble detected patterns consistent with deceptive or fraudulent websites and classified this as{" "}
                    <strong className="text-cyber-danger font-semibold">phishing</strong>.
                  </>
                )}
              </p>
            </div>

            {/* Probability Bars */}
            <div className="space-y-3 rounded-xl border border-surface-border bg-surface/40 p-4">
              <div>
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-gray-400">Phishing Probability</span>
                  <span className={`font-semibold ${isPhishing ? "text-cyber-danger" : "text-gray-300"}`}>
                    {phishingProbPct}%
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-surface-elevated">
                  <div
                    className="h-full bg-cyber-danger transition-all duration-700 ease-out"
                    style={{ width: `${phishingProbPct}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-gray-400">Legitimate Probability</span>
                  <span className={`font-semibold ${isLegitimate ? "text-cyber-safe" : "text-gray-300"}`}>
                    {legitProbPct}%
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-surface-elevated">
                  <div
                    className="h-full bg-cyber-safe transition-all duration-700 ease-out"
                    style={{ width: `${legitProbPct}%` }}
                  />
                </div>
              </div>
            </div>

            <p className="text-[11px] text-gray-400">
              * Note: Probability denotes the Random Forest ensemble split ratio for this feature vector, not historical accuracy.
            </p>
          </div>
        </div>

        {/* AI Security Explanation (Powered by Groq) */}
        <div className="border-t border-surface-border bg-surface/50 p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 flex items-center gap-2 font-bold">
              <Sparkles className="h-4 w-4 text-primary" aria-hidden="true" />
              AI SECURITY EXPLANATION
            </h3>
            <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[11px] font-medium bg-primary/10 text-primary border border-primary/20 w-fit">
              Powered by Groq
            </span>
          </div>

          {result.ai_explanation_available && result.ai_explanation ? (
            <div className="rounded-xl border border-surface-border bg-background/50 p-4 sm:p-5">
              <div className="prose prose-invert max-w-none text-sm text-gray-300 leading-relaxed space-y-3 whitespace-pre-line font-sans">
                {result.ai_explanation}
              </div>
              <div className="mt-4 pt-3 border-t border-surface-border/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-gray-400 font-mono">
                <span>Interpretive synthesis of Random Forest V3 lexical features</span>
                <span className="text-cyber-safe">• RF V3 Authoritative</span>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-surface-border/60 bg-background/30 p-4 text-sm text-gray-400 flex items-start gap-3">
              <HelpCircle className="h-5 w-5 text-gray-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <p className="font-medium text-gray-300">
                  AI explanation unavailable. Random Forest analysis is still available.
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  AI explanation service is not currently active on the backend.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Technical Details Panel */}
        <div className="border-t border-surface-border bg-surface/80 p-6 sm:p-8">
          <h4 className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
            <Server className="h-4 w-4 text-primary" aria-hidden="true" />
            Inspection Technical Telemetry
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-lg border border-surface-border bg-background/60 p-3">
              <span className="text-[11px] font-mono uppercase tracking-wide text-gray-400 block mb-1">
                Analyzed URL
              </span>
              <p className="font-mono text-xs text-white break-all select-all font-medium">
                {result.url}
              </p>
            </div>

            <div className="rounded-lg border border-surface-border bg-background/60 p-3">
              <span className="text-[11px] font-mono uppercase tracking-wide text-gray-400 block mb-1">
                Classifier Algorithm
              </span>
              <p className="font-mono text-xs text-white font-medium flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                Random Forest V3 (100 Trees)
              </p>
            </div>

            <div className="rounded-lg border border-surface-border bg-background/60 p-3">
              <span className="text-[11px] font-mono uppercase tracking-wide text-gray-400 block mb-1">
                Feature Schema
              </span>
              <p className="font-mono text-xs text-white font-medium flex items-center gap-1.5">
                <Layers className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                21 URL Lexical Features
              </p>
            </div>

            <div className="rounded-lg border border-surface-border bg-background/60 p-3">
              <span className="text-[11px] font-mono uppercase tracking-wide text-gray-400 block mb-1">
                Execution Mode
              </span>
              <p className="font-mono text-xs text-white font-medium flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                Zero-Crawl (&lt;1ms latency)
              </p>
            </div>
          </div>

          {/* Security Disclaimer */}
          <div className="mt-5 rounded-lg border border-surface-border/60 bg-surface-card/40 p-3 text-center sm:text-left">
            <p className="text-[11px] text-gray-400 leading-relaxed">
              <strong>Security Notice:</strong> PhishGuard provides a machine-learning based assessment and should not be treated as a guarantee of website safety. Always exercise caution before submitting credentials or downloading attachments.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
