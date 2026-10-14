import React from "react";
import { Link2, Sliders, Cpu } from "lucide-react";

export const HowItWorks: React.FC = () => {
  const steps = [
    {
      step: "01",
      title: "URL Input",
      icon: Link2,
      description:
        "The user submits a target URL. The system validates the protocol (HTTP/HTTPS) and domain structure without issuing network requests to the untrusted host.",
    },
    {
      step: "02",
      title: "Feature Extraction",
      icon: Sliders,
      description:
        "The backend extracts exactly 21 lexical, statistical, and structural features (character continuation, length ratios, digit frequencies, obfuscation tokens, and TLD probabilities) in microseconds.",
    },
    {
      step: "03",
      title: "Random Forest Inference",
      icon: Cpu,
      description:
        "A 100-tree Random Forest ensemble evaluates the feature vector and votes to determine the final classification, generating a verified phishing probability and calibrated risk score.",
    },
  ];

  return (
    <section id="how-it-works" className="py-16 sm:py-24 border-t border-surface-border">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="font-mono text-xs uppercase tracking-wider text-primary font-semibold">
            Zero-Crawl Detection Pipeline
          </span>
          <h2 className="mt-2 text-3xl sm:text-4xl font-bold tracking-tight text-white">
            How PhishGuard Works
          </h2>
          <p className="mt-3 text-sm sm:text-base text-gray-400 leading-relaxed">
            PhishGuard detects phishing links through pure structural and lexical analysis, avoiding the operational failure and security hazards of live webpage crawling.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {steps.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.step}
                className="glass-panel relative rounded-2xl p-6 sm:p-8 transition-all duration-300 hover:border-surface-borderHover hover:bg-surface-elevated/60 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <span className="font-mono text-3xl font-extrabold text-primary/40">
                      {item.step}
                    </span>
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-primary/20 bg-primary/10 text-primary">
                      <Icon className="h-5 w-5" aria-hidden="true" />
                    </div>
                  </div>

                  <h3 className="text-lg font-bold text-white mb-2">
                    {item.title}
                  </h3>

                  <p className="text-sm text-gray-400 leading-relaxed">
                    {item.description}
                  </p>
                </div>

                <div className="mt-6 pt-4 border-t border-surface-border/40 font-mono text-[11px] text-gray-500">
                  {item.step === "01" && "Zero network crawling required"}
                  {item.step === "02" && "21 tabular lexical metrics"}
                  {item.step === "03" && "100-estimator decision ensemble"}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
