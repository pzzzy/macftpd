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
          "primary": "#17645b",
          "primary-content": "#f5fffb",
          "secondary": "#4f46e5",
          "secondary-content": "#f7f7ff",
          "accent": "#d97706",
          "accent-content": "#111827",
          "neutral": "#202427",
          "neutral-content": "#f4f7f6",
          "base-100": "#f6f8f7",
          "base-200": "#edf1ef",
          "base-300": "#d6dfda",
          "base-content": "#151819",
          "info": "#0f6d8f",
          "success": "#237a4c",
          "warning": "#b45309",
          "error": "#9f1d1d",
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
