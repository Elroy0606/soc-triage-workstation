/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        obsidian: "#070b14",
        net: "#38bdf8",   // cyan: IPs, hops, OSINT pivots
        safe: "#34d399",  // emerald: internal assets, PASS, clean output
        warn: "#fbbf24",  // amber: defanged indicators, medium alerts
        risk: "#fb7185",  // coral: hashes, FAIL, MITRE detections
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "Consolas", "monospace"],
      },
      keyframes: {
        breathe: {
          "0%, 100%": { opacity: "0.55", transform: "scale(1)" },
          "50%": { opacity: "0.9", transform: "scale(1.08)" },
        },
        drift: {
          from: { backgroundPosition: "0 0" },
          to: { backgroundPosition: "28px 28px" },
        },
      },
      animation: {
        breathe: "breathe 12s ease-in-out infinite",
        drift: "drift 18s linear infinite",
      },
    },
  },
  plugins: [],
};
