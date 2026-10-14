/**
 * PhishGuard API Service Abstraction
 * Handles communication with the FastAPI backend.
 */

import type { AnalyzeRequest, AnalyzeResponse, HealthResponse } from "../types/api";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

/**
 * Checks system health and model loading readiness.
 */
export async function getHealth(): Promise<HealthResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(`${API_BASE_URL}/api/health`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`Health check failed with HTTP ${res.status}`);
    }

    return await res.json();
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof Error) {
      if (err.name === "AbortError") {
        throw new Error("Backend connection timed out (5s). Is FastAPI running?");
      }
      throw new Error(`Unable to connect to PhishGuard backend (${err.message}). Verify server on ${API_BASE_URL}.`);
    }
    throw new Error("Unknown error while connecting to backend.");
  }
}

/**
 * Submits a URL to the FastAPI backend for Random Forest phishing analysis.
 */
export async function analyzeUrl(url: string): Promise<AnalyzeResponse> {
  const cleanUrl = url.trim();

  if (!cleanUrl) {
    throw new Error("Please enter a URL to analyze.");
  }

  // Basic client-side pre-validation
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
    throw new Error("URL must begin with http:// or https:// (e.g. https://example.com)");
  }

  const payload: AnalyzeRequest = { url: cleanUrl };
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      let detailMsg = `HTTP Error ${res.status}`;
      try {
        const errorJson = await res.json();
        if (errorJson.detail) {
          if (Array.isArray(errorJson.detail)) {
            detailMsg = errorJson.detail.map((d: any) => d.msg || JSON.stringify(d)).join(". ");
          } else {
            detailMsg = errorJson.detail;
          }
        }
      } catch {
        // Fall back to status text
        detailMsg = res.statusText || detailMsg;
      }

      if (res.status === 422) {
        throw new Error(`Invalid URL: ${detailMsg.replace("Value error, ", "")}`);
      }
      if (res.status === 503) {
        throw new Error("Machine learning model is currently not loaded on the backend.");
      }
      throw new Error(detailMsg);
    }

    const data: AnalyzeResponse = await res.json();
    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof Error) {
      if (err.name === "AbortError") {
        throw new Error("Request timed out (10s). The backend took too long to respond.");
      }
      // Check for TypeError: Failed to fetch (indicates server offline or CORS issue)
      if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        throw new Error(`Cannot reach PhishGuard backend at ${API_BASE_URL}. Ensure the FastAPI server is running.`);
      }
      throw err;
    }
    throw new Error("An unexpected error occurred during URL analysis.");
  }
}
