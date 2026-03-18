import type { Config } from "tailwindcss";

export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        "ga-red": "var(--ga-red)",
        "ga-red-dark": "var(--ga-red-dark)",
        "ga-red-light": "var(--ga-red-light)",
        "ga-charcoal": "var(--ga-charcoal)",
        "ga-gray-dark": "var(--ga-gray-dark)",
        "ga-gray": "var(--ga-gray)",
        "ga-gray-light": "var(--ga-gray-light)",
        "ga-bg": "var(--ga-bg)",
      },
    },
  },
  plugins: [],
} satisfies Config;
