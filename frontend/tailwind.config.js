/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#070b16",
          900: "#0b1224",
          800: "#121a32",
          700: "#1a2442",
        },
        accent: {
          blue: "#3b82f6",
          cyan: "#22d3ee",
        },
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 0 0 1px rgba(148, 163, 184, 0.12)",
      },
    },
  },
  plugins: [],
};
