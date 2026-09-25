/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkbg: "#0b0f17",
        darkcard: "#111827",
        darkborder: "#1f2937",
      }
    },
  },
  plugins: [],
}
