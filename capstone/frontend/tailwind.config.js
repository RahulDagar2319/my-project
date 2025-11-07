/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      keyframes: {
        'toast-in': {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'toast-out': {
            '0%': { transform: 'translateY(0)', opacity: '1' },
            '100%': { transform: 'translateY(-100%)', opacity: '0' },
          }
      },
      animation: {
        'toast-in': 'toast-in 0.5s ease-out forwards',
        'toast-out': 'toast-out 0.5s ease-in forwards',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}