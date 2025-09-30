import { computed } from 'vue'
import type { Theme } from '../types'

/**
 */
export function useOAuthButtonStyles(
  variables: any,
  theme: Theme = 'light'
) {
  
  const getThemeColors = () => {
    return {
      background: 'var(--auth-ui-oauth-bg)',
      backgroundHover: 'var(--auth-ui-oauth-bg-hover)',
      backgroundActive: 'var(--auth-ui-oauth-bg-active)',
      border: 'var(--auth-ui-oauth-border)',
      borderHover: 'var(--auth-ui-oauth-border-hover)',
      text: 'var(--auth-ui-oauth-text)',
      shadow: 'var(--auth-ui-oauth-shadow)',
      shadowHover: 'var(--auth-ui-oauth-shadow-hover)',
      shadowActive: 'var(--auth-ui-oauth-shadow-active)'
    }
  }

  
  const colors = computed(() => getThemeColors())

  
  const baseButtonStyle = computed(() => {
    const space = variables.value.space || {}
    const fonts = variables.value.fonts || {}
    const fontSizes = variables.value.fontSizes || {}
    const fontWeights = variables.value.fontWeights || {}
    const radii = variables.value.radii || {}
    
    return {
      width: '100%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: space.buttonPadding || 'var(--auth-ui-space-md) var(--auth-ui-space-lg)',
      border: `1px solid var(--auth-ui-oauth-border)`,
      borderRadius: radii.borderRadiusButton || 'var(--auth-ui-radius-md)',
      backgroundColor: 'var(--auth-ui-oauth-bg)',
      color: 'var(--auth-ui-oauth-text)',
      fontSize: fontSizes.baseButtonSize || 'var(--auth-ui-text-sm)',
      fontFamily: fonts.buttonFontFamily || 'ui-sans-serif, system-ui, sans-serif',
      fontWeight: fontWeights.buttonFontWeight || 'var(--auth-ui-font-medium)',
      lineHeight: '1.25',
      cursor: 'pointer',
      boxShadow: 'var(--auth-ui-oauth-shadow)',
      transition: 'all 0.15s ease-in-out',
      outline: 'none',
      textDecoration: 'none',
      userSelect: 'none' as const
    }
  })

  
  const hoverStyle = computed(() => ({
    backgroundColor: colors.value.backgroundHover,
    borderColor: colors.value.borderHover,
    boxShadow: colors.value.shadowHover
  }))

  
  const activeStyle = computed(() => ({
    backgroundColor: colors.value.backgroundActive,
    borderColor: colors.value.borderHover,
    boxShadow: colors.value.shadowActive
  }))

  
  const disabledStyle = computed(() => ({
    opacity: '0.6',
    cursor: 'not-allowed',
    boxShadow: colors.value.shadow
  }))

  
  const iconStyle = computed(() => {
    const space = variables.value.space || {}
    
    return {
      width: '20px',
      height: '20px',
      marginRight: space.spaceMedium || '8px',
      flexShrink: 0
    }
  })

  return {
    baseButtonStyle,
    hoverStyle,
    activeStyle,
    disabledStyle,
    iconStyle,
    colors
  }
}
