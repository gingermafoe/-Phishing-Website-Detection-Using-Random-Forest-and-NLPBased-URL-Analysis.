import React, { useState, useEffect } from "react";
import { Search, Loader2, ArrowRight, AlertCircle, Sparkles } from "lucide-react";
import type { AnalysisStatus } from "../types/api";

interface UrlScannerProps {
  status: AnalysisStatus;
  errorMessage: string | null;
  onAnalyze: (url: string) => void;
}

const LOADING_STEPS = [
  "Analyzing URL structure...",
  "Extracting 21 lexical features...",
  "Evaluating Random Forest ensemble...",
];

const PRESET_EXAMPLES = [
  { label: "Google (Legitimate)", url: "https://www.google.com" },
  { label: "Southbank Mosaics (Dataset)", url: "https://www.southbankmosaics.com" },
  { label: "PayPal Spoof (Phishing)", url: "http://paypal-security-update.account-verify.com/login.php?user=123&token=abc" },
  { label: "Free Domain Threat (Dataset)", url: "http://www.shprakserf.gq" },
];

export const UrlScanner: React.FC<UrlScannerProps> = ({
  status,
  errorMessage,
  onAnalyze,
}) => {
  const [urlInput, setUrlInput] = useState("");
  const [stepIndex, setStepIndex] = useState(0);

  const isLoading = status === "loading";

  // Cycle through short technical loading steps during analysis
  useEffect(() => {
    let interval: any = null;
    if (isLoading) {
      setStepIndex(0);
      interval = setInterval(() => {
        setStepIndex((prev) => (prev + 1) % LOADING_STEPS.length);
      }, 450);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isLoading]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() || isLoading) return;
    onAnalyze(urlInput.trim());
  };

  const handlePresetClick = (presetUrl: string) => {
    setUrlInput(presetUrl);
    onAnalyze(presetUrl);
  };

  return (
    <div id="scanner" className="w-full max-w-3xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="glass-panel-elevated relative flex flex-col sm:flex-row items-stretch rounded-2xl p-2 sm:p-2.5 transition-all duration-300 focus-within:border-primary focus-within:glow-primary border border-surface-border">
          {/* Input icon */}
          <div className="hidden sm:flex items-center pl-3.5 pr-2 text-gray-500">
            <Search className="h-5 w-5 text-gray-400" aria-hidden="true" />
          </div>

          {/* URL Input Box */}
          <input
            id="url-input"
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            disabled={isLoading}
            placeholder="https://example.com"
            aria-label="URL to inspect for phishing"
            className="w-full bg-transparent px-4 py-3.5 sm:py-3 font-mono text-sm sm:text-base text-white placeholder-gray-500 focus:outline-none disabled:opacity-60"
            autoComplete="off"
            spellCheck="false"
          />

          {/* Submit Button */}
          <button
            id="analyze-button"
            type="submit"
            disabled={isLoading || !urlInput.trim()}
            className="mt-2 sm:mt-0 inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3.5 sm:py-3 text-sm font-semibold text-gray-950 transition-all hover:bg-primary-hover focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 focus:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 font-sans shadow-lg shadow-primary/20 shrink-0"
          >
            {isLoading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin text-gray-950" aria-hidden="true" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <span>Analyze URL</span>
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </>
            )}
          </button>
        </div>

        {/* Loading Progress State */}
        {isLoading && (
          <div
            className="mt-3 flex items-center justify-center gap-2 rounded-lg bg-surface/80 py-2 px-3 text-xs font-mono text-primary"
            role="status"
            aria-live="polite"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            <span>{LOADING_STEPS[stepIndex]}</span>
          </div>
        )}

        {/* Error Notification Banner */}
        {errorMessage && (
          <div
            className="mt-4 flex items-start gap-3 rounded-xl border border-cyber-dangerBorder bg-cyber-dangerSubtle/80 p-4 text-xs sm:text-sm text-red-200"
            role="alert"
            aria-live="assertive"
          >
            <AlertCircle className="h-5 w-5 shrink-0 text-cyber-danger mt-0.5" aria-hidden="true" />
            <div className="flex-1">
              <span className="font-semibold text-white block mb-0.5">Analysis Failed</span>
              <p className="text-gray-300 leading-relaxed">{errorMessage}</p>
            </div>
          </div>
        )}
      </form>

      {/* Preset Example Chips */}
      <div className="mt-5 flex flex-wrap items-center justify-center gap-2 text-xs">
        <span className="text-gray-400 font-mono text-[11px] flex items-center gap-1 mr-1">
          <Sparkles className="h-3 w-3 text-primary" aria-hidden="true" />
          Test Sample:
        </span>
        {PRESET_EXAMPLES.map((example) => (
          <button
            key={example.url}
            type="button"
            onClick={() => handlePresetClick(example.url)}
            disabled={isLoading}
            className="rounded-lg border border-surface-border bg-surface px-2.5 py-1 font-mono text-[11px] text-gray-300 transition-colors hover:border-primary/50 hover:bg-surface-elevated hover:text-white focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
          >
            {example.label}
          </button>
        ))}
      </div>
    </div>
  );
};
