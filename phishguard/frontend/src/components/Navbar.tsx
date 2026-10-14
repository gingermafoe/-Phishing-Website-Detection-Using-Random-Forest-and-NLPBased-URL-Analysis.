import React from "react";
import { Shield } from "lucide-react";
import type { HealthResponse } from "../types/api";

interface NavbarProps {
  health: HealthResponse | null;
  healthLoading: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ health, healthLoading }) => {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-surface-border bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary shadow-[0_0_15px_rgba(110,168,255,0.15)]">
            <Shield className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-lg font-bold tracking-wider text-white">
                PHISHGUARD
              </span>
              <span className="hidden rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-primary border border-surface-border sm:inline-block">
                v3.0 ML
              </span>
            </div>
            <p className="text-xs text-gray-400">
              AI-Powered Phishing Detection
            </p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-6 text-sm text-gray-400 font-medium">
          <a
            href="#scanner"
            className="transition-colors hover:text-white focus:outline-none focus:ring-1 focus:ring-primary rounded px-1"
          >
            Scanner
          </a>
          <a
            href="#how-it-works"
            className="transition-colors hover:text-white focus:outline-none focus:ring-1 focus:ring-primary rounded px-1"
          >
            How It Works
          </a>
          <a
            href="#model"
            className="transition-colors hover:text-white focus:outline-none focus:ring-1 focus:ring-primary rounded px-1"
          >
            Model
          </a>
          <a
            href="#features"
            className="transition-colors hover:text-white focus:outline-none focus:ring-1 focus:ring-primary rounded px-1"
          >
            Features
          </a>
        </nav>

        {/* System Health Status Indicator */}
        <div className="flex items-center gap-3">
          <div
            className="flex items-center gap-2 rounded-full border border-surface-border bg-surface px-3 py-1 text-xs font-mono text-gray-300"
            role="status"
            aria-live="polite"
          >
            {healthLoading ? (
              <>
                <span className="h-2 w-2 animate-pulse rounded-full bg-gray-500" />
                <span className="text-[11px] text-gray-400">CHECKING MODEL...</span>
              </>
            ) : health?.model_loaded ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyber-safe opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-cyber-safe" />
                </span>
                <span className="text-[11px] font-semibold text-gray-300">
                  MODEL ONLINE
                </span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-cyber-danger" />
                <span className="text-[11px] font-semibold text-cyber-danger">
                  MODEL OFFLINE
                </span>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
