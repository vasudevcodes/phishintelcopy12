/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#F0F9F8',
          100: '#D6EFEA',
          200: '#AFDFD8',
          300: '#7ECAC0',
          400: '#4AB1A5',
          500: '#168C83', // primary accent
          600: '#12726B',
          700: '#0F5B56',
          800: '#0C4743',
          900: '#083330',
        },
        navy: {
          950: '#0E1424',
          900: '#172033', // primary text
          800: '#1F2C45',
          700: '#2A3B5C',
          600: '#3D517A',
        },
        slate: {
          50: '#F8FAFC',
          100: '#F1F5F9',
          200: '#E2E8F0',
          300: '#CBD5E1',
          400: '#94A3B8',
          500: '#64748B',
          600: '#475569',
          700: '#334155',
          800: '#1E293B',
          900: '#0F172A',
        },
        surface: {
          bg: '#F7F8FA',    // warm off-white main background
          card: '#FFFFFF',  // pure white card background
          subtle: '#F4F5F7',// subtle neutral surface
          hover: '#F0F2F5', // subtle hover surface
          border: '#E4E7EC',// neutral border
          borderStrong: '#D0D5DD',
        },
      },
      fontFamily: {
        mono: ['IBM Plex Mono', 'JetBrains Mono', 'Consolas', 'monospace'],
        sans: ['IBM Plex Sans', 'Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(16, 24, 40, 0.04)',
        'card': '0 0 0 1px rgba(23, 32, 51, 0.04), 0 1px 2px 0 rgba(16, 24, 40, 0.05), 0 4px 12px -4px rgba(16, 24, 40, 0.06)',
        'card-hover': '0 0 0 1px rgba(22, 140, 131, 0.18), 0 2px 4px 0 rgba(16, 24, 40, 0.06), 0 12px 24px -8px rgba(16, 24, 40, 0.12)',
        'ring-brand': '0 0 0 4px rgba(22, 140, 131, 0.14)',
        'dropdown': '0 10px 15px -3px rgba(16, 24, 40, 0.08), 0 4px 6px -4px rgba(16, 24, 40, 0.04)',
      },
      keyframes: {
        'fade-in': { '0%': { opacity: '0', transform: 'translateY(6px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        'scan': { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(400%)' } },
      },
      animation: {
        'fade-in': 'fade-in 0.35s ease-out both',
        'scan': 'scan 1.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
