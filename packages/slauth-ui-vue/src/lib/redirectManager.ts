

const PRESERVE_PARAMS = ['redirect', 'state']


export const getPreservedParams = () => {
  const currentParams = new URLSearchParams(window.location.search)
  const preserved: Record<string, string> = {}
  
  PRESERVE_PARAMS.forEach(param => {
    const value = currentParams.get(param)
    if (value) {
      preserved[param] = value
    }
  })
  
  return preserved
}


export const buildUrlWithPreservedParams = (basePath: string, additionalParams: Record<string, string> = {}) => {
  const preserved = getPreservedParams()
  const allParams = { ...preserved, ...additionalParams }
  
  const params = new URLSearchParams()
  Object.entries(allParams).forEach(([key, value]) => {
    params.set(key, value)
  })
  
  const queryString = params.toString()
  return queryString ? `${basePath}?${queryString}` : basePath
}


export const calculateRedirectUrl = (
  followRedirect: boolean = true,
  configRedirectTo?: string,
  defaultRedirect: string = '/'
): string => {
  const preserved = getPreservedParams()
  
  if (followRedirect && preserved.redirect) {
    return preserved.redirect
  }
  
  return configRedirectTo || defaultRedirect
}
