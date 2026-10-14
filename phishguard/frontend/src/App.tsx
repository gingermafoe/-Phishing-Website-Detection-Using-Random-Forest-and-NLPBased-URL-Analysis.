import React, { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { Hero } from "./components/Hero";
import { ResultCard } from "./components/ResultCard";
import { HowItWorks } from "./components/HowItWorks";
import { ModelSection } from "./components/ModelSection";
import { FeatureGrid } from "./components/FeatureGrid";
import { Footer } from "./components/Footer";
import { getHealth, analyzeUrl } from "./services/api";
import type { AnalyzeResponse, HealthResponse, AnalysisStatus } from "./types/api";

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [status, setStatus] = useState<AnalysisStatus>("idle");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Check backend health on initial load once (no continuous polling)
  useEffect(() => {
    let isMounted = true;
    const checkStatus = async () => {
      try {
        setHealthLoading(true);
        const data = await getHealth();
        if (isMounted) {
          setHealth(data);
        }
      } catch (err) {
        if (isMounted) {
          setHealth({ status: "offline", model: "Random Forest", model_loaded: false });
        }
      } finally {
        if (isMounted) {
          setHealthLoading(false);
        }
      }
    };

    checkStatus();

    return () => {
      isMounted = false;
    };
  }, []);

  const handleAnalyze = async (url: string) => {
    setStatus("loading");
    setErrorMessage(null);

    try {
      const data = await analyzeUrl(url);
      setResult(data);
      setStatus("success");

      // Smooth scroll to results
      setTimeout(() => {
        const resultElement = document.getElementById("result-panel");
        if (resultElement) {
          resultElement.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
      }, 100);
    } catch (err: unknown) {
      setStatus("error");
      setResult(null);
      if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage("An unexpected network or system error occurred.");
      }
    }
  };

  return (
    <div className="min-h-screen bg-background text-gray-200 flex flex-col font-sans selection:bg-primary/20 selection:text-primary">
      {/* Top Navigation */}
      <Navbar health={health} healthLoading={healthLoading} />

      {/* Main Container */}
      <main className="flex-1">
        {/* Hero Section & Scanner Form */}
        <Hero
          status={status}
          errorMessage={errorMessage}
          onAnalyze={handleAnalyze}
        />

        {/* Live Analysis Result Panel */}
        {status === "success" && result && (
          <div className="px-4 pb-12 sm:pb-16">
            <ResultCard result={result} />
          </div>
        )}

        {/* Architectural Explanations */}
        <HowItWorks />

        {/* Machine Learning Model Telemetry */}
        <ModelSection />

        {/* 21 Tabular Production Feature Grid */}
        <FeatureGrid />
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
};

export default App;
