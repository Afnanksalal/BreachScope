import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans:  ["var(--font-sans)", "system-ui", "-apple-system", "sans-serif"],
        mono:  ["ui-monospace", "SF Mono", "Menlo", "Consolas", "monospace"],
        serif: ["var(--font-serif)", "Georgia", "serif"],
      },
      colors: {
        // Monochromatic surface system — pure black base
        surface: {
          0:   "#000000",
          50:  "#0a0a0a",
          100: "#111111",
          200: "#1c1c1e",  // iOS dark card
          300: "#2c2c2e",  // iOS dark elevated
          400: "#3a3a3c",  // iOS separator
        },
        // Keep breach accent for UI elements (dashboard, status, etc.)
        // Use much more sparingly on the landing page
        breach: {
          50:  "#f3f0ff",
          100: "#e9e2ff",
          200: "#d4c5ff",
          300: "#b59eff",
          400: "#9470ff",
          500: "#7c57ff",
          600: "#6640f5",
          700: "#5230cc",
          800: "#4025a8",
          900: "#2e1880",
          950: "#1a0d4d",
        },
        scope: {
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
        },
      },
      animation: {
        "fade-up": "fadeUp 0.55s ease forwards",
        "fade-in": "fadeIn 0.7s ease forwards",
      },
      keyframes: {
        fadeUp: {
          "0%":   { opacity: "0", transform: "translateY(16px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        fadeIn: {
          "0%":   { opacity: "0" },
          "100%": { opacity: "1" },
        },
      },
      backgroundImage: {
        // Very subtle dark gradient for section separation — no purple
        "gradient-dark": "linear-gradient(180deg, #000 0%, #0a0a0a 100%)",
      },
    },
  },
  plugins: [],
};

export default config;
