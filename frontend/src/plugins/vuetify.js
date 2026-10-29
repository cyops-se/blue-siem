import '@mdi/font/css/materialdesignicons.css'
import 'vuetify/styles'
import { createVuetify } from 'vuetify'
import { en, sv } from 'vuetify/locale'

let stored = null
try {
  stored = localStorage.getItem('theme')
} catch {
  // storage unavailable
}

export default createVuetify({
  locale: { locale: 'sv', fallback: 'en', messages: { sv, en } },
  theme: {
    defaultTheme: stored || 'dark',
    themes: {
      dark: {
        dark: true,
        colors: {
          background: '#0f141a',
          surface: '#171e26',
          primary: '#42a5f5',
          secondary: '#90a4ae',
        },
      },
      light: {
        dark: false,
        colors: {
          background: '#f4f6f8',
          primary: '#1565c0',
          secondary: '#546e7a',
        },
      },
    },
  },
  defaults: {
    VCard: { rounded: 'lg' },
    VTextField: { variant: 'outlined', density: 'comfortable' },
    VTextarea: { variant: 'outlined', density: 'comfortable' },
    VSelect: { variant: 'outlined', density: 'comfortable' },
    VCombobox: { variant: 'outlined', density: 'comfortable' },
  },
})
