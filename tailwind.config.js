module.exports = {
  content: [
    "./internal/httpapi/templates/**/*.html",
    "./internal/httpapi/*.go",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["InterVariable", "Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["SFMono-Regular", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  daisyui: {
    themes: [
      {
        macftpd: {
          "primary": "#2dd4bf",
          "primary-content": "#042f2e",
          "secondary": "#a78bfa",
          "secondary-content": "#1f1147",
          "accent": "#f59e0b",
          "accent-content": "#1f1300",
          "neutral": "#0f172a",
          "neutral-content": "#e5edf5",
          "base-100": "#0b1117",
          "base-200": "#111a24",
          "base-300": "#233142",
          "base-content": "#e7eef6",
          "info": "#38bdf8",
          "success": "#34d399",
          "warning": "#fbbf24",
          "error": "#f87171",
          "--rounded-box": "0.5rem",
          "--rounded-btn": "0.375rem",
          "--rounded-badge": "999px",
          "--animation-btn": "0.12s",
          "--animation-input": "0.12s",
          "--btn-focus-scale": "1",
          "--border-btn": "1px",
          "--tab-border": "1px",
          "--tab-radius": "0.375rem",
        },
      },
    ],
  },
  plugins: [require("daisyui")],
};
