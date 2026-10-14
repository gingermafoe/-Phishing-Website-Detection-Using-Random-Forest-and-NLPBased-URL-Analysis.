import React from "react";
import { Cpu, Database, CheckCircle, BarChart3, AlertOctagon, Layers } from "lucide-react";

export const ModelSection: React.FC = () => {
  const specs = [
    { label: "Classifier Algorithm", value: "Random Forest V3 (100 Trees)", icon: Cpu },
    { label: "Training Dataset", value: "PhiUSIIL Phishing URL Dataset", icon: Database },
    { label: "Production Feature Vector", value: "21 URL Lexical Features", icon: Layers },
    { label: "Inference Latency", value: "< 1 millisecond (Zero-Crawl)", icon: BarChart3 },
    { label: "Held-Out Test Accuracy", value: "99.66% (47,074 samples)", icon: CheckCircle },
    { label: "False Positive Rate (FPR)", value: "0.54% (Low false alarm)", icon: AlertOctagon },
  ];

  return (
    <section id="model" className="py-16 sm:py-24 border-t border-surface-border bg-surface/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="font-mono text-xs uppercase tracking-wider text-primary font-semibold">
            Applied Machine Learning Architecture
          </span>
          <h2 className="mt-2 text-3xl sm:text-4xl font-bold tracking-tight text-white">
            Machine Learning Model
          </h2>
          <p className="mt-3 text-sm sm:text-base text-gray-400 leading-relaxed">
            Trained and verified on over 235,000 real-world URLs. The model evaluates high-dimensional tabular non-linear interactions without using NLP or visiting untrusted destinations.
          </p>
        </div>

        {/* Technical Specs Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {specs.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.label}
                className="glass-panel rounded-xl p-5 border border-surface-border transition-colors hover:border-surface-borderHover"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-elevated text-primary border border-surface-border">
                    <Icon className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <span className="text-xs font-mono uppercase tracking-wide text-gray-400">
                    {item.label}
                  </span>
                </div>
                <p className="font-mono text-base font-semibold text-white pl-11">
                  {item.value}
                </p>
              </div>
            );
          })}
        </div>

        {/* Technical Transparency Callout */}
        <div className="mt-10 max-w-3xl mx-auto rounded-xl border border-surface-border bg-surface-card p-5 text-center sm:text-left">
          <div className="flex flex-col sm:flex-row items-center gap-4">
            <div className="h-10 w-10 shrink-0 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-mono text-xs font-bold">
              ML
            </div>
            <div>
              <h4 className="text-sm font-semibold text-white font-mono">
                Pure Lexical Architecture Guarantee
              </h4>
              <p className="mt-1 text-xs text-gray-400 leading-relaxed">
                The production scanner operates strictly on the 21 URL lexical features extracted at request time. It does NOT analyze webpage HTML, execute JavaScript, or scrape third-party web content, providing resilience against offline phishing lures and eliminating server-side SSRF exposure.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
