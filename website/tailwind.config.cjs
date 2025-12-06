const docsPreset = require("@usecross/docs/tailwind.preset");

/** @type {import('tailwindcss').Config} */
module.exports = {
  presets: [docsPreset],
  content: [
    "./frontend/**/*.{ts,tsx}",
    "./node_modules/@usecross/docs/**/*.{js,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // Override heading font to use Typekit roc-grotesk
        heading: ['"roc-grotesk"', 'sans-serif'],
      },
    },
  },
};
