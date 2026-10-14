import React from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  Cpu,
  Layers,
  Zap,
  HelpCircle,
  AlertTriangle,
  CheckCircle,
  Clock,
  Globe,
  Radio,
  FileText,
  Lock,
} from "lucide-react";
import type { AnalyzeResponse, ThreatIntelProviderResult } from "../types/api";
import { RiskScore } from "./RiskScore";

interface ResultCardProps {
  result: AnalyzeResponse;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result }) => {
  const isLegitimate = result.label === 1;
  const isPhishing = result.label === 0;

  const phishingProbPct =
    result.phishing_probability !== undefined
      ? Math.round(result.phishing_probability * 100)
      : result.risk_score;
  const legitProbPct = 100 - phishingProbPct;

  const features = result.features || {};
  const tiProviders = result.threat_intel_providers || [];
  const tiSummary = result.threat_intel_summary;

  // Check if there is disagreement between Random Forest and Threat Intelligence
  const anyTiMalicious = tiProviders.some((p) => p.status === "malicious_match");
  const anyTiClean = tiProviders.some((p) => p.status === "no_match_found");
  const hasDisagreement =
    (isLegitimate && anyTiMalicious) || (isPhishing && anyTiClean && !anyTiMalicious);

  const getStatusBadge = (status: ThreatIntelProviderResult["status"]) => {
    switch (status) {
      case "malicious_match":
        return {
          bg: "bg-red-500/10 border-red-500/30 text-red-400",
          icon: <ShieldAlert className="h-3.5 w-3.5 text-red-400" />,
          label: "Threat Match",
        };
      case "no_match_found":
        return {
          bg: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
          icon: <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />,
          label: "No Match Found",
        };
      case "unknown":
        return {
          bg: "bg-purple-500/10 border-purple-500/30 text-purple-400",
          icon: <HelpCircle className="h-3.5 w-3.5 text-purple-400" />,
          label: "Unknown / Unseen",
        };
      case "unavailable":
        return {
          bg: "bg-amber-500/10 border-amber-500/30 text-amber-400",
          icon: <Clock className="h-3.5 w-3.5 text-amber-400" />,
          label: "Unavailable / Timed Out",
        };
      case "error":
        return {
          bg: "bg-orange-500/10 border-orange-500/30 text-orange-400",
          icon: <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />,
          label: "Query Error",
        };
      case "not_configured":
      default:
        return {
          bg: "bg-gray-500/10 border-gray-500/30 text-gray-400",
          icon: <InfoIcon className="h-3.5 w-3.5 text-gray-400" />,
          label: "Not Configured",
        };
    }
  };

  return (
    <section
      id="result-panel"
      className="mx-auto mt-8 max-w-4xl animate-fadeIn space-y-6"
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
        {/* 1. Header Banner */}
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
                  {isLegitimate ? "LEGITIMATE WEBSITE" : "PHISHING THREAT DETECTED"}
                </span>
                <span className="text-gray-500">•</span>
                <span className="text-xs text-gray-400 font-mono">
                  Random Forest V3 (Authoritative)
                </span>
              </div>
              <h2 className="text-lg sm:text-xl font-bold tracking-tight text-white break-all">
                PhishGuard Analysis: <span className="font-mono text-primary font-normal text-base">{result.url}</span>
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
              {isLegitimate ? "Class 1: Legitimate" : "Class 0: Phishing"}
            </span>
          </div>
        </div>

        {/* Source Disagreement Alert Banner (if applicable) */}
        {hasDisagreement && (
          <div className="bg-amber-500/10 border-b border-amber-500/30 px-6 py-3.5 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-200 leading-relaxed font-sans">
              <strong className="font-semibold text-amber-300">Model & Intelligence Discrepancy: </strong>
              {isLegitimate && anyTiMalicious && (
                <span>
                  The authoritative Random Forest V3 classifier evaluated this URL's lexical syntax as legitimate, but one or more external threat intelligence providers report active malicious listings. External intelligence may have observed domain misuse or newly compromised hosting. Both independent assessments are displayed below without modification.
                </span>
              )}
              {isPhishing && anyTiClean && !anyTiMalicious && (
                <span>
                  The authoritative Random Forest V3 classifier detected structural and lexical anomalies indicative of phishing, while external providers reported no active reputation listing. Absence of reputation records is common for newly generated or zero-day phishing lures.
                </span>
              )}
            </div>
          </div>
        )}

        {/* 2. Main Authoritative Classification Panel */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 sm:p-8">
          {/* Left: Risk Score Gauge */}
          <div className="flex flex-col items-center justify-center rounded-xl border border-surface-border bg-surface/60 p-4">
            <RiskScore score={result.risk_score} />
          </div>

          {/* Middle & Right: Probabilities & Authoritative Assessment */}
          <div className="md:col-span-2 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold tracking-wide text-gray-400 uppercase font-mono">
                  Authoritative Random Forest V3 Assessment
                </h3>
                {result.analyzed_at && (
                  <span className="text-[11px] font-mono text-gray-400 flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(result.analyzed_at).toLocaleTimeString()} UTC
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-sm text-gray-300 leading-relaxed">
                {isLegitimate ? (
                  <>
                    The Random Forest V3 ensemble analyzed the 21 URL lexical features and determined the URL conforms to authentic website structures, classifying it as{" "}
                    <strong className="text-cyber-safe font-semibold">LEGITIMATE</strong> with a risk score of{" "}
                    <strong className="text-cyber-safe font-mono">{result.risk_score}/100</strong>.
                  </>
                ) : (
                  <>
                    The Random Forest V3 ensemble identified suspicious lexical, structural, or entropy signatures consistent with credential harvesting or deceptive lures, classifying it as{" "}
                    <strong className="text-cyber-danger font-semibold">PHISHING</strong> with a risk score of{" "}
                    <strong className="text-cyber-danger font-mono">{result.risk_score}/100</strong>.
                  </>
                )}
              </p>
            </div>

            {/* Probability Bars */}
            <div className="space-y-3 rounded-xl border border-surface-border bg-surface/40 p-4">
              <div>
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-gray-400">Phishing Probability P(Phishing)</span>
                  <span className={`font-semibold ${isPhishing ? "text-cyber-danger" : "text-gray-300"}`}>
                    {phishingProbPct}% ({result.phishing_probability ?? (result.risk_score / 100).toFixed(4)})
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
                  <span className="text-gray-400">Legitimate Probability P(Legitimate)</span>
                  <span className={`font-semibold ${isLegitimate ? "text-cyber-safe" : "text-gray-300"}`}>
                    {legitProbPct}% ({(1 - (result.phishing_probability ?? result.risk_score / 100)).toFixed(4)})
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

            <p className="text-[11px] text-gray-400 font-mono">
              * Authoritative ML decision: 100-tree decision ensemble on 21 canonical URL lexical features. Zero destination web crawl.
            </p>
          </div>
        </div>

        {/* 3. Threat Intelligence Scrutiny Section */}
        <div className="border-t border-surface-border bg-surface/50 p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-gray-200 flex items-center gap-2 font-bold">
                <Radio className="h-4 w-4 text-cyan-400" />
                Live Threat Intelligence Scrutiny
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Independent reputation checks from external security databases.
              </p>
            </div>
            {tiSummary && (
              <span
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[11px] font-medium border ${
                  tiSummary.status === "malicious_match"
                    ? "bg-red-500/10 text-red-400 border-red-500/30"
                    : tiSummary.status === "clean_matches"
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    : "bg-gray-500/10 text-gray-400 border-gray-500/30"
                }`}
              >
                {tiSummary.status === "malicious_match"
                  ? `${tiSummary.malicious_count} Threat Detected`
                  : tiSummary.status === "clean_matches"
                  ? "0 Threat Matches"
                  : "Intelligence Inconclusive"}
              </span>
            )}
          </div>

          {/* Provider Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            {tiProviders.map((provider) => {
              const badge = getStatusBadge(provider.status);
              return (
                <div
                  key={provider.provider}
                  className="rounded-xl border border-surface-border bg-background/50 p-4 flex flex-col justify-between space-y-3"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-xs text-white font-mono flex items-center gap-1.5">
                        <Globe className="h-3.5 w-3.5 text-primary" />
                        {provider.provider}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] font-medium border ${badge.bg}`}
                      >
                        {badge.icon}
                        {badge.label}
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs text-gray-300">
                      <div>
                        <span className="text-gray-400 text-[11px] block font-mono">Evidence:</span>
                        <p className="font-mono text-xs text-gray-200 break-words font-medium">
                          {provider.evidence}
                        </p>
                      </div>
                      <div>
                        <span className="text-gray-400 text-[11px] block font-mono">Status Meaning:</span>
                        <p className="text-[11px] text-gray-400 leading-normal">
                          {provider.explanation}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-surface-border/50 text-[10px] font-mono text-gray-400 flex items-center justify-between">
                    <span>Checked:</span>
                    <span>
                      {provider.checked_at
                        ? new Date(provider.checked_at).toLocaleTimeString() + " UTC"
                        : "N/A"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Overall Threat Intelligence Summary */}
          {tiSummary && (
            <div className="rounded-xl border border-surface-border/70 bg-surface-card/60 p-4 text-xs text-gray-300">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold text-gray-200 mb-1">
                <FileText className="h-3.5 w-3.5 text-cyan-400" />
                Overall Intelligence Synthesis:
              </div>
              <p className="leading-relaxed text-gray-300">{tiSummary.summary}</p>
            </div>
          )}
        </div>

        {/* 4. Numbered Technical Explanation (Exact 8-Point Structure) */}
        <div className="border-t border-surface-border bg-surface/70 p-6 sm:p-8">
          <div className="mb-5">
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-200 flex items-center gap-2 font-bold">
              <Cpu className="h-4 w-4 text-primary" />
              Technical URL Feature & Security Explanation
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Detailed technical breakdown of the actual 21 features supplied to the Random Forest V3 classifier.
            </p>
          </div>

          <div className="space-y-3 font-sans text-xs">
            {/* 1. Secure Protocol */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">1.</span> Secure Protocol (IsHTTPS)
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  IsHTTPS = {features.IsHTTPS !== undefined ? String(features.IsHTTPS) : "N/A"}
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                {features.IsHTTPS === 1 ? (
                  <>
                    The URL utilizes HTTPS transport encryption (<code className="text-gray-300 font-mono">IsHTTPS = 1</code>). While encryption prevents passive network eavesdropping, modern phishing campaigns routinely acquire valid automated SSL/TLS certificates (e.g. via Let's Encrypt or Cloudflare). HTTPS alone does NOT verify website legitimacy.
                  </>
                ) : (
                  <>
                    The URL transmits over unencrypted HTTP (<code className="text-gray-300 font-mono">IsHTTPS = 0</code>). The absence of transport encryption significantly elevates risk, as legitimate modern services handling sensitive logins mandate HTTPS.
                  </>
                )}
              </p>
            </div>

            {/* 2. URL and Domain Structure */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">2.</span> URL and Domain Structure
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  Length: {features.URLLength ?? "N/A"} chars | Subdomains: {features.NoOfSubDomain ?? "N/A"}
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                Evaluates structural hierarchy: Total URL Length (<code className="text-gray-300 font-mono">URLLength = {features.URLLength ?? "N/A"}</code>), Domain Name Length (<code className="text-gray-300 font-mono">DomainLength = {features.DomainLength ?? "N/A"}</code>), and Canonical Subdomain Count (<code className="text-gray-300 font-mono">NoOfSubDomain = {features.NoOfSubDomain ?? "N/A"}</code>). Excessive subdomains or abnormally inflated lengths often signify domain nesting used to conceal true destinations.
              </p>
            </div>

            {/* 3. Obfuscation Indicators */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">3.</span> Obfuscation Indicators (%-Encoding)
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  Obfuscated Chars: {features.NoOfObfuscatedChar ?? 0}
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                Checks for percent-encoded obfuscation sequences: <code className="text-gray-300 font-mono">HasObfuscation = {features.HasObfuscation ?? 0}</code>, <code className="text-gray-300 font-mono">NoOfObfuscatedChar = {features.NoOfObfuscatedChar ?? 0}</code>, and <code className="text-gray-300 font-mono">ObfuscationRatio = {features.ObfuscationRatio ?? 0}</code>. Phishers frequently employ hex-encoding (e.g. %20, %2E) to evade naive pattern matchers and URL filters.
              </p>
            </div>

            {/* 4. Digits and Special Characters */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">4.</span> Digits and Special Characters
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  Digits: {features.NoOfDegitsInURL ?? 0} ({((features.DegitRatioInURL ?? 0) * 100).toFixed(1)}%)
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                Measures numerical and punctuation density: <code className="text-gray-300 font-mono">NoOfDegitsInURL = {features.NoOfDegitsInURL ?? 0}</code>, <code className="text-gray-300 font-mono">DegitRatioInURL = {features.DegitRatioInURL ?? 0}</code>, <code className="text-gray-300 font-mono">NoOfEqualsInURL = {features.NoOfEqualsInURL ?? 0}</code>, <code className="text-gray-300 font-mono">NoOfQMarkInURL = {features.NoOfQMarkInURL ?? 0}</code>, <code className="text-gray-300 font-mono">NoOfAmpersandInURL = {features.NoOfAmpersandInURL ?? 0}</code>, and <code className="text-gray-300 font-mono">SpacialCharRatioInURL = {features.SpacialCharRatioInURL ?? 0}</code>. Dense tokenization or credential query strings increase phishing probability.
              </p>
            </div>

            {/* 5. Lexical Statistics */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">5.</span> Lexical & Distributional Statistics
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  TLD Prob: {features.TLDLegitimateProb ?? "N/A"} | Char Prob: {features.URLCharProb ?? "N/A"}
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                Empirical dataset priors: Top-Level Domain Legitimacy Probability (<code className="text-gray-300 font-mono">TLDLegitimateProb = {features.TLDLegitimateProb ?? "N/A"}</code>), Global URL Character Frequency (<code className="text-gray-300 font-mono">URLCharProb = {features.URLCharProb ?? "N/A"}</code>), and Character Continuation Rate (<code className="text-gray-300 font-mono">CharContinuationRate = {features.CharContinuationRate ?? "N/A"}</code>). Rare or cheap TLDs alongside high repetition rates are common phishing markers.
              </p>
            </div>

            {/* 6. Random Forest Assessment */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">6.</span> Random Forest V3 Authoritative Assessment
                </span>
                <span
                  className={`font-mono text-[11px] px-2 py-0.5 rounded border font-semibold ${
                    isLegitimate
                      ? "bg-cyber-safe/10 text-cyber-safe border-cyber-safe/30"
                      : "bg-cyber-danger/10 text-cyber-danger border-cyber-danger/30"
                  }`}
                >
                  {result.prediction.toUpperCase()} (Score: {result.risk_score}/100)
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                The 100-tree Random Forest decision ensemble evaluated all 21 lexical features in parallel. The predicted class is <strong className="text-white">{result.prediction.toUpperCase()}</strong> with a calibrated confidence probability of <strong className="text-white">{(result.probability * 100).toFixed(2)}%</strong> and an authoritative cybersecurity risk score of <strong className="text-white">{result.risk_score}/100</strong>.
              </p>
            </div>

            {/* 7. Threat-Intelligence Evidence */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">7.</span> Threat-Intelligence Corroboration
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface border border-surface-border text-gray-300">
                  {tiProviders.filter((p) => p.status === "malicious_match").length} Threat Flags
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed">
                Independent threat intelligence providers (Google Safe Browsing, VirusTotal, PhishTank) were queried for registered domain reputation. Findings:{" "}
                <span className="text-gray-300">
                  {tiSummary ? tiSummary.summary : "No threat intelligence providers configured."}
                </span>{" "}
                {hasDisagreement && (
                  <strong className="text-amber-300">
                    Note: Random Forest prediction remains authoritative and is not overwritten by reputation mismatches.
                  </strong>
                )}
              </p>
            </div>

            {/* 8. Groq Interpretation */}
            <div className="rounded-lg border border-surface-border bg-background/50 p-3.5">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-bold text-gray-200 flex items-center gap-1.5">
                  <span className="text-primary font-mono">8.</span> Groq AI Supplementary Security Scrutiny
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary">
                  Non-Authoritative Interpretation
                </span>
              </div>

              {result.ai_explanation_available && result.ai_explanation ? (
                <div className="mt-2 text-gray-300 leading-relaxed space-y-2 whitespace-pre-line bg-surface/50 rounded p-3 border border-surface-border/50">
                  {result.ai_explanation}
                </div>
              ) : (
                <p className="text-gray-400 leading-relaxed mt-1">
                  AI security explanation is currently inactive or unavailable. The authoritative Random Forest classification and threat-intelligence telemetry remain fully intact.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* 5. Technical Telemetry Footer Grid */}
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
                Classifier Architecture
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
                21 Canonical URL Lexical Features
              </p>
            </div>

            <div className="rounded-lg border border-surface-border bg-background/60 p-3">
              <span className="text-[11px] font-mono uppercase tracking-wide text-gray-400 block mb-1">
                Execution Model
              </span>
              <p className="font-mono text-xs text-white font-medium flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                Zero-Crawl Lexical ML
              </p>
            </div>
          </div>

          {/* 6. Exact Mandatory Important Disclaimer */}
          <div className="mt-6 rounded-xl border border-cyber-danger/20 bg-cyber-danger/5 p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <Lock className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h5 className="font-mono text-xs font-bold uppercase tracking-wider text-amber-300">
                  Important Disclaimer & Operational Notice
                </h5>
                <p className="text-xs text-gray-300 leading-relaxed font-sans">
                  PhishGuard combines Random Forest URL-feature analysis with the reputation checks available during this scan. External providers may not know about newly created phishing URLs, and unavailable checks are not evidence of safety. Groq provides a supplementary explanation and does not determine or change the Random Forest prediction. Unless a separately implemented inspection mechanism explicitly confirms otherwise, PhishGuard has not visited or inspected the destination webpage. Do not enter credentials or sensitive information solely because a URL is classified as legitimate.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

// Internal small helper icon for "not configured"
function InfoIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
      aria-hidden="true"
      {...props}
    >
      <circle cx={12} cy={12} r={10} />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 16v-4m0-4h.01" />
    </svg>
  );
}
