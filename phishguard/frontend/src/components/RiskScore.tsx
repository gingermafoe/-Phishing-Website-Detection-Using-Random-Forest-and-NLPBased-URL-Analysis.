import React from "react";

interface RiskScoreProps {
  score: number; // 0 to 100
}

export const RiskScore: React.FC<RiskScoreProps> = ({ score }) => {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

  // Determine styling tier based on calibrated thresholds
  let strokeColor = "#22C55E"; // Green
  let badgeBg = "rgba(34, 197, 94, 0.12)";
  let badgeBorder = "rgba(34, 197, 94, 0.3)";
  let textLabel = "LOW RISK";

  if (clampedScore > 69) {
    strokeColor = "#EF4444"; // Red
    badgeBg = "rgba(239, 68, 68, 0.12)";
    badgeBorder = "rgba(239, 68, 68, 0.3)";
    textLabel = "HIGH THREAT";
  } else if (clampedScore > 25) {
    strokeColor = "#F59E0B"; // Amber
    badgeBg = "rgba(245, 158, 11, 0.12)";
    badgeBorder = "rgba(245, 158, 11, 0.3)";
    textLabel = "MODERATE RISK";
  }

  // Circular gauge calculations
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center p-4">
      {/* Circular SVG Gauge */}
      <div className="relative flex items-center justify-center">
        <svg
          className="h-32 w-32 -rotate-90 transform"
          viewBox="0 0 100 100"
          aria-hidden="true"
        >
          {/* Background circle track */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke="#181C22"
            strokeWidth="8"
          />
          {/* Value progress arc */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke={strokeColor}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span
            className="font-mono text-3xl font-bold tracking-tight text-white"
            aria-label={`Risk score ${clampedScore} out of 100`}
          >
            {clampedScore}
          </span>
          <span className="font-mono text-[10px] tracking-wider text-gray-400 uppercase">
            / 100
          </span>
        </div>
      </div>

      {/* Risk Badge */}
      <div
        className="mt-3 rounded-full border px-3 py-1 font-mono text-[11px] font-semibold tracking-wider"
        style={{
          backgroundColor: badgeBg,
          borderColor: badgeBorder,
          color: strokeColor,
        }}
      >
        {textLabel}
      </div>
      <p className="mt-1 text-[11px] text-gray-400">
        Cybersecurity Risk Index
      </p>
    </div>
  );
};
