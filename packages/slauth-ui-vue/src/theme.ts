import { defineComponent, provide, inject } from 'vue'
import type { InjectionKey } from 'vue'

export interface ThemeVariables {
  default: {
    colors: {
      brand?: string
      brandAccent?: string
      brandButtonText?: string
      defaultButtonBackground?: string
      defaultButtonBackgroundHover?: string
      defaultButtonBackgroundActive?: string
      defaultButtonBorder?: string
      defaultButtonBorderHover?: string
      defaultButtonText?: string
      dividerBackground?: string
      inputBackground?: string
      inputBorder?: string
      inputBorderHover?: string
      inputBorderFocus?: string
      inputText?: string
      inputLabelText?: string
      inputPlaceholder?: string
      messageText?: string
      messageTextDanger?: string
      anchorTextColor?: string
      anchorTextHoverColor?: string
    }
    space?: {
      spaceSmall?: string
      spaceMedium?: string
      spaceLarge?: string
      buttonPadding?: string
      inputPadding?: string
    }
    fontSizes?: {
      baseBodySize?: string
      baseInputSize?: string
      baseLabelSize?: string
      baseButtonSize?: string
    }
    fonts?: {
      bodyFontFamily?: string
      buttonFontFamily?: string
      inputFontFamily?: string
      labelFontFamily?: string
    }
    fontWeights?: {
      buttonFontWeight?: string
      inputFontWeight?: string
      labelFontWeight?: string
    }
    lineHeights?: {
      buttonLineHeight?: string
      inputLineHeight?: string
      labelLineHeight?: string
    }
    radii?: {
      borderRadiusButton?: string
      borderRadiusInput?: string
    }
  }
}

export interface ThemeConfig {
  theme?: 'light' | 'dark' | 'auto'
  variables?: ThemeVariables
}

// Default theme variables
export const defaultTheme: ThemeVariables = {
  default: {
    colors: {
      brand: '#3b82f6',
      brandAccent: '#2563eb',
      brandButtonText: '#ffffff',
      defaultButtonBackground: '#ffffff',
      defaultButtonBackgroundHover: '#f9fafb',
      defaultButtonBackgroundActive: '#f3f4f6',
      defaultButtonBorder: '#e5e7eb',
      defaultButtonBorderHover: '#d1d5db',
      defaultButtonText: '#374151',
      dividerBackground: '#e5e7eb',
      inputBackground: '#ffffff',
      inputBorder: '#d1d5db',
      inputBorderHover: '#9ca3af',
      inputBorderFocus: '#3b82f6',
      inputText: '#111827',
      inputLabelText: '#374151',
      inputPlaceholder: '#9ca3af',
      messageText: '#374151',
      messageTextDanger: '#dc2626',
      anchorTextColor: '#3b82f6',
      anchorTextHoverColor: '#2563eb'
    },
    space: {
      spaceSmall: '4px',
      spaceMedium: '8px',
      spaceLarge: '16px',
      buttonPadding: '8px 16px',
      inputPadding: '8px 12px'
    },
    fontSizes: {
      baseBodySize: '14px',
      baseInputSize: '14px',
      baseLabelSize: '14px',
      baseButtonSize: '14px'
    },
    fonts: {
      bodyFontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif',
      buttonFontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif',
      inputFontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif',
      labelFontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif'
    },
    fontWeights: {
      buttonFontWeight: '500',
      inputFontWeight: '400',
      labelFontWeight: '500'
    },
    lineHeights: {
      buttonLineHeight: '1.25',
      inputLineHeight: '1.5',
      labelLineHeight: '1.5'
    },
    radii: {
      borderRadiusButton: '6px',
      borderRadiusInput: '6px'
    }
  }
}

// Theme injection key
export const themeKey: InjectionKey<ThemeConfig> = Symbol('slauth-ui-theme')

// Theme provider component
export const ThemeProvider = defineComponent({
  name: 'AiraAuthThemeProvider',
  props: {
    theme: {
      type: String as () => 'light' | 'dark' | 'auto',
      default: 'light'
    },
    variables: {
      type: Object as () => ThemeVariables,
      default: () => defaultTheme
    }
  },
  setup(props, { slots }) {
    const themeConfig: ThemeConfig = {
      theme: props.theme,
      variables: props.variables
    }

    provide(themeKey, themeConfig)

    return () => slots.default?.()
  }
})

// Hook to use theme
export function useTheme(): ThemeConfig {
  return inject(themeKey, {
    theme: 'light',
    variables: defaultTheme
  })
}

// Generate CSS variables from theme
export function generateCSSVariables(variables: ThemeVariables): Record<string, string> {
  const cssVars: Record<string, string> = {}
  
  const flattenObject = (obj: any, prefix = '') => {
    Object.keys(obj).forEach(key => {
      const value = obj[key]
      const cssKey = prefix ? `${prefix}-${key}` : key
      
      if (typeof value === 'object' && value !== null) {
        flattenObject(value, cssKey)
      } else {
        cssVars[`--auth-ui-${cssKey.replace(/([A-Z])/g, '-$1').toLowerCase()}`] = value
      }
    })
  }
  
  flattenObject(variables.default)
  return cssVars
}
