import GoogleGSIProvider from './google_gsi.vue'
import GooglePKCEProvider from './google_pkce.vue'
import FacebookProvider from './facebook.vue'
import MockProvider from './mock.vue'


export const allProviders = {
  google_gie: GoogleGSIProvider,
  google: GooglePKCEProvider,
  facebook: FacebookProvider,
  mock: MockProvider,
}


export const getProvider = (name: string) => {
  return allProviders[name as keyof typeof allProviders]
}

