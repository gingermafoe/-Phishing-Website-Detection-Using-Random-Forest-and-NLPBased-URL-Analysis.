/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#08090A",
        surface: {
          DEFAULT: "#0E1012",
          card: "#13161A",
          elevated: "#181C22",
          border: "#232830",
          borderHover: "#353D4A",
        },
        primary: {
          DEFAULT: "#6EA8FF",
          hover: "#8AB9FF",
          subtle: "rgba(110, 168, 255, 0.12)",
          glow: "rgba(110, 168, 255, 0.25)",
        },
        cyber: {
          safe: "#22C55E",
          safeSubtle: "rgba(34, 197, 94, 0.12)",
          safeBorder: "rgba(34, 197, 94, 0.3)",
          danger: "#EF4444",
          dangerSubtle: "rgba(239, 68, 68, 0.12)",
          dangerBorder: "rgba(239, 68, 68, 0.3)",
          warning: "#F59E0B",
          warningSubtle: "rgba(245, 158, 11, 0.12)",
        }
      },
      fontFamily: {
        sans: ['Inter', 'Manrope', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      }
    },
  },
  plugins: [],
}
