/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  // Vuetify ships its own reset; Tailwind is used for layout utilities only.
  corePlugins: { preflight: false },
  // Scope utilities under #app so they win over Vuetify's component CSS,
  // which is loaded lazily per route and would otherwise override them.
  important: '#app',
  theme: { extend: {} },
  plugins: [],
}
