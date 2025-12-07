/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './frontend/**/*.{ts,tsx}',
    './templates/**/*.html',
    './node_modules/@usecross/docs/src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 10%, white)',
          100: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 20%, white)',
          200: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 40%, white)',
          300: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 60%, white)',
          400: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 80%, white)',
          500: 'var(--color-primary-500, #6366f1)',
          600: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 90%, black)',
          700: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 70%, black)',
          800: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 50%, black)',
          900: 'color-mix(in srgb, var(--color-primary-500, #6366f1) 30%, black)',
        },
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
}
