import React from "react";
import { Terminal } from "lucide-react";

interface FeatureItem {
  name: string;
  category: "Length & Structure" | "Character Statistics" | "Obfuscation" | "Security & Probability";
  description: string;
}

const PRODUCTION_FEATURES: FeatureItem[] = [
  { name: "URLLength", category: "Length & Structure", description: "Total character count of the URL path and query." },
  { name: "DomainLength", category: "Length & Structure", description: "Character length of the hostname / netloc." },
  { name: "IsDomainIP", category: "Length & Structure", description: "Binary indicator for IPv4 / IPv6 host addressing." },
  { name: "TLDLength", category: "Length & Structure", description: "Length of the top-level domain extension." },
  { name: "NoOfSubDomain", category: "Length & Structure", description: "Count of sub-levels prepended to the domain." },
  { name: "HasObfuscation", category: "Obfuscation", description: "Binary flag indicating presence of % hex-encoding." },
  { name: "NoOfObfuscatedChar", category: "Obfuscation", description: "Count of percent-encoded hexadecimal byte sequences." },
  { name: "ObfuscationRatio", category: "Obfuscation", description: "Ratio of obfuscated bytes to total URL length." },
  { name: "NoOfLettersInURL", category: "Character Statistics", description: "Total count of alphabetical characters [a-zA-Z]." },
  { name: "LetterRatioInURL", category: "Character Statistics", description: "Proportion of alphabetic letters across the URL." },
  { name: "NoOfDegitsInURL", category: "Character Statistics", description: "Total count of numeric digit characters [0-9]." },
  { name: "DegitRatioInURL", category: "Character Statistics", description: "Proportion of digits relative to total length." },
  { name: "NoOfEqualsInURL", category: "Character Statistics", description: "Frequency of '=' query parameter assignment tokens." },
  { name: "NoOfQMarkInURL", category: "Character Statistics", description: "Frequency of '?' query string delimiter tokens." },
  { name: "NoOfAmpersandInURL", category: "Character Statistics", description: "Frequency of '&' parameter separator delimiters." },
  { name: "NoOfOtherSpecialCharsInURL", category: "Character Statistics", description: "Count of special characters (-, _, ., @, /)." },
  { name: "SpacialCharRatioInURL", category: "Character Statistics", description: "Proportion of special punctuation characters." },
  { name: "IsHTTPS", category: "Security & Probability", description: "Binary indicator for secure TLS protocol scheme." },
  { name: "CharContinuationRate", category: "Character Statistics", description: "Longest continuous run of identical character types." },
  { name: "TLDLegitimateProb", category: "Security & Probability", description: "Empirical legitimate frequency for the TLD extension." },
  { name: "URLCharProb", category: "Security & Probability", description: "Statistical character transition probability." },
];

export const FeatureGrid: React.FC = () => {
  return (
    <section id="features" className="py-16 sm:py-24 border-t border-surface-border">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="font-mono text-xs uppercase tracking-wider text-primary font-semibold">
            Input Vector Inspection
          </span>
          <h2 className="mt-2 text-3xl sm:text-4xl font-bold tracking-tight text-white">
            21 Production Feature Categories
          </h2>
          <p className="mt-3 text-sm sm:text-base text-gray-400 leading-relaxed">
            The Random Forest model consumes strictly these 21 tabular features. No raw text is fed directly into the classifier, preventing memorization and maintaining zero-dependency speed.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 max-w-6xl mx-auto">
          {PRODUCTION_FEATURES.map((feat, idx) => (
            <div
              key={feat.name}
              className="glass-panel rounded-xl p-4 border border-surface-border transition-all hover:border-surface-borderHover hover:bg-surface-elevated/40"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs font-bold text-primary flex items-center gap-1.5">
                  <Terminal className="h-3 w-3 text-gray-500" aria-hidden="true" />
                  {feat.name}
                </span>
                <span className="font-mono text-[10px] text-gray-500">
                  #{idx + 1}
                </span>
              </div>

              <p className="text-xs text-gray-300 leading-relaxed">
                {feat.description}
              </p>

              <div className="mt-3 pt-2 border-t border-surface-border/40">
                <span className="inline-block rounded bg-surface px-2 py-0.5 font-mono text-[10px] text-gray-400">
                  {feat.category}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
